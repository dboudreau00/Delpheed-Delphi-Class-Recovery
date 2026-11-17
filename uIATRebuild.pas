unit uIATRebuild;

{$IFDEF FPC}
  {$MODE DELPHI}
  {$H+}
{$ENDIF}

{
  uIATRebuild - reconstruct the import table of an unpacked dump so it loads again.

  After unpacking, the stub has resolved every API the program needs and written
  the addresses into the Import Address Table in memory. But the on-disk import
  *directory* (the descriptors the loader reads) is gone. This rebuilds it, the
  way Scylla/ImpREC do:

    1. Enumerate the loaded modules of the live target (base, size, name).
    2. Scan the dumped image for the IAT: the longest run of pointer slots that
       all point into a loaded DLL (self-pointers into the image are ignored).
    3. Resolve each pointer to (DLL, function) by reading that DLL's export
       table out of the live process.
    4. Group the resolved pointers by DLL (contiguous runs) and emit a new
       import directory - descriptors + import lookup tables + hint/name tables
       + DLL name strings - into a fresh section appended to the file, with the
       FirstThunk of each descriptor pointing back at the existing IAT slots.
    5. Point the PE's import data directory at the new descriptors.

  MUST be called while the target is still alive and frozen at the OEP (its DLLs
  loaded, its IAT resolved).

  32-bit (PE32) targets. Build 32-bit.
}

{$IFNDEF FPC}
  {$WARN SYMBOL_PLATFORM OFF}
{$ENDIF}

interface

uses
  Windows, SysUtils, Classes, Generics.Collections,
  {$IFDEF FPC}JwaTlHelp32{$ELSE}TlHelp32{$ENDIF};

type
  {$IFDEF FPC}
  TIATLog = procedure(const Msg: string) of object;
  {$ELSE}
  TIATLog = reference to procedure(const Msg: string);
  {$ENDIF}

  TIATResult = record
    Success: Boolean;
    Message: string;
    IATStartRVA: Cardinal;
    IATSize: Cardinal;
    Imports: Integer;
    Unresolved: Integer;
    Descriptors: Integer;
    OutFile: string;
  end;

  TImp = record
    ByName: Boolean;
    Name: AnsiString;
    Ordinal: Word;
  end;

  TImpGroup = record
    ModIndex: Integer;
    StartRVA: Cardinal;          // FirstThunk: RVA of the first IAT slot in the group
    Entries: TArray<TImp>;
    ILTOffset: Cardinal;         // offset of this group's ILT inside the new blob
  end;

  TModExports = class
  public
    Index: Integer;
    Base: NativeUInt;
    Size: NativeUInt;
    Name: string;
    IsImage: Boolean;
    Parsed: Boolean;
    HasExports: Boolean;
    ExpBase: Cardinal;
    ExpDirRVA: Cardinal;
    ExpDirSize: Cardinal;
    FuncRVAs: TArray<Cardinal>;
    NameByIndex: TArray<AnsiString>;
    RVAToIndex: TDictionary<Cardinal, Integer>;
    constructor Create;
    destructor Destroy; override;
  end;

  TIATRebuilder = class
  private
    FLog: TIATLog;
    FProc: THandle;
    FImageBase: NativeUInt;
    FSizeOfImage: Cardinal;
    FMods: TObjectList<TModExports>;
    procedure Log(const S: string);
    function RBytes(Addr: NativeUInt; var Buf; Size: NativeUInt): Boolean;
    function RU32(Addr: NativeUInt): Cardinal;
    function RU16(Addr: NativeUInt): Word;
    function RCStr(Addr: NativeUInt): AnsiString;
    procedure EnumModules;
    procedure ParseModule(M: TModExports);
    function ModuleOf(VA: NativeUInt): TModExports;
    function Resolve(VA: NativeUInt; out ModIdx: Integer; out Imp: TImp): Boolean;
  public
    constructor Create(hProcess: THandle; ALog: TIATLog = nil);
    destructor Destroy; override;
    function RebuildImports(const InDumpFile, OutFixedFile: string;
      StubStartRVA: Cardinal = 0; StubEndRVA: Cardinal = 0): TIATResult;
  end;

implementation

function K32Read(hProcess: THandle; lpBaseAddress, lpBuffer: Pointer;
  nSize: NativeUInt; lpRead: PNativeUInt): BOOL; stdcall;
  external kernel32 name 'ReadProcessMemory';
function K32GetPid(hProcess: THandle): DWORD; stdcall;
  external kernel32 name 'GetProcessId';

const
  MIN_IMPORTS = 3;
  MAX_ZERO_GAP = 4;
  IMPORT_BY_ORDINAL = $80000000;
  DDIR_IMPORT    = 1;
  DDIR_BASERELOC = 5;
  DDIR_BOUND     = 11;
  DDIR_IAT       = 12;
  DLL_CHAR_DYNAMIC_BASE = $0040;
  SNAP_MOD_FLAGS = $00000008 or $00000010;   // TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32

function Align(V, A: Cardinal): Cardinal;
begin
  Result := (V + A - 1) and not (A - 1);
end;

{ TModExports }

constructor TModExports.Create;
begin
  inherited Create;
  RVAToIndex := TDictionary<Cardinal, Integer>.Create;
end;

destructor TModExports.Destroy;
begin
  RVAToIndex.Free;
  inherited Destroy;
end;

{ TIATRebuilder }

constructor TIATRebuilder.Create(hProcess: THandle; ALog: TIATLog);
begin
  inherited Create;
  FProc := hProcess;
  FLog := ALog;
  FMods := TObjectList<TModExports>.Create(True);
end;

destructor TIATRebuilder.Destroy;
begin
  FMods.Free;
  inherited Destroy;
end;

procedure TIATRebuilder.Log(const S: string);
begin
  if Assigned(FLog) then FLog(S);
end;

function TIATRebuilder.RBytes(Addr: NativeUInt; var Buf; Size: NativeUInt): Boolean;
var
  got: NativeUInt;
begin
  got := 0;
  Result := K32Read(FProc, Pointer(Addr), @Buf, Size, @got) and (got = Size);
end;

function TIATRebuilder.RU32(Addr: NativeUInt): Cardinal;
begin
  Result := 0;
  RBytes(Addr, Result, 4);
end;

function TIATRebuilder.RU16(Addr: NativeUInt): Word;
begin
  Result := 0;
  RBytes(Addr, Result, 2);
end;

function TIATRebuilder.RCStr(Addr: NativeUInt): AnsiString;
var
  b: Byte;
  n: Integer;
begin
  Result := '';
  n := 0;
  while n < 512 do
  begin
    b := 0;
    if not RBytes(Addr + NativeUInt(n), b, 1) then Break;
    if b = 0 then Break;
    Result := Result + AnsiChar(b);
    Inc(n);
  end;
end;

procedure TIATRebuilder.EnumModules;
var
  snap: THandle;
  me: TModuleEntry32;
  M: TModExports;
  pid: DWORD;
  tries: Integer;
begin
  pid := K32GetPid(FProc);
  snap := INVALID_HANDLE_VALUE;
  for tries := 1 to 5 do
  begin
    snap := CreateToolhelp32Snapshot(SNAP_MOD_FLAGS, pid);
    if snap <> INVALID_HANDLE_VALUE then Break;
    if GetLastError <> ERROR_BAD_LENGTH then Break;
    Sleep(10);
  end;
  if snap = INVALID_HANDLE_VALUE then Exit;
  try
    FillChar(me, SizeOf(me), 0);
    me.dwSize := SizeOf(me);
    if Module32First(snap, me) then
      repeat
        M := TModExports.Create;
        M.Index := FMods.Count;
        M.Base := NativeUInt(me.modBaseAddr);
        M.Size := me.modBaseSize;
        M.Name := string(me.szModule);
        M.IsImage := (M.Base = FImageBase);
        FMods.Add(M);
      until not Module32Next(snap, me);
  finally
    CloseHandle(snap);
  end;
  Log(Format('%d modules loaded in target.', [FMods.Count]));
end;

procedure TIATRebuilder.ParseModule(M: TModExports);
var
  lfanew, optOfs, ddBase: NativeUInt;
  magic: Word;
  numFuncs, numNames, aof, aon, aoo, i: Cardinal;
  nameRVA, rva: Cardinal;
  ordv: Word;
  raw: TBytes;
  prevIdx: Integer;
begin
  M.Parsed := True;
  M.HasExports := False;
  if RU16(M.Base) <> $5A4D then Exit;               // 'MZ'
  lfanew := M.Base + RU32(M.Base + $3C);
  if RU32(lfanew) <> $00004550 then Exit;           // 'PE'#0#0
  optOfs := lfanew + 24;
  magic := RU16(optOfs);
  if magic = $20B then
    ddBase := optOfs + 112
  else
    ddBase := optOfs + 96;                           // PE32

  M.ExpDirRVA  := RU32(ddBase);                      // export = index 0
  M.ExpDirSize := RU32(ddBase + 4);
  if M.ExpDirRVA = 0 then Exit;

  M.ExpBase := RU32(M.Base + M.ExpDirRVA + 16);
  numFuncs  := RU32(M.Base + M.ExpDirRVA + 20);
  numNames  := RU32(M.Base + M.ExpDirRVA + 24);
  aof       := RU32(M.Base + M.ExpDirRVA + 28);
  aon       := RU32(M.Base + M.ExpDirRVA + 32);
  aoo       := RU32(M.Base + M.ExpDirRVA + 36);
  if (numFuncs = 0) or (numFuncs > 100000) then Exit;

  SetLength(M.FuncRVAs, numFuncs);
  SetLength(raw, numFuncs * 4);
  if not RBytes(M.Base + aof, raw[0], numFuncs * 4) then Exit;
  for i := 0 to numFuncs - 1 do
    M.FuncRVAs[i] := PCardinal(@raw[i * 4])^;

  SetLength(M.NameByIndex, numFuncs);
  if numNames > 100000 then numNames := 0;
  for i := 0 to numNames - 1 do
  begin
    nameRVA := RU32(M.Base + aon + i * 4);
    ordv    := RU16(M.Base + aoo + i * 2);
    if ordv < numFuncs then
      if M.NameByIndex[ordv] = '' then
        M.NameByIndex[ordv] := RCStr(M.Base + nameRVA);
  end;

  M.RVAToIndex.Clear;
  for i := 0 to numFuncs - 1 do
  begin
    rva := M.FuncRVAs[i];
    if rva = 0 then Continue;
    // Skip forwarder strings sitting inside the export directory
    if (M.ExpDirSize > 0) and (rva >= M.ExpDirRVA) and (rva < M.ExpDirRVA + M.ExpDirSize) then
      Continue;
    if not M.RVAToIndex.TryGetValue(rva, prevIdx) then
      M.RVAToIndex.Add(rva, Integer(i))
    else if (M.NameByIndex[prevIdx] = '') and (M.NameByIndex[i] <> '') then
      M.RVAToIndex.AddOrSetValue(rva, Integer(i));
  end;

  M.HasExports := True;
end;

function TIATRebuilder.ModuleOf(VA: NativeUInt): TModExports;
var
  i: Integer;
begin
  Result := nil;
  for i := 0 to FMods.Count - 1 do
    if (VA >= FMods[i].Base) and (VA < FMods[i].Base + FMods[i].Size) then
      Exit(FMods[i]);
end;

function TIATRebuilder.Resolve(VA: NativeUInt; out ModIdx: Integer; out Imp: TImp): Boolean;
var
  M: TModExports;
  funcRVA: Cardinal;
  idx: Integer;
begin
  Result := False;
  ModIdx := -1;
  Imp.ByName := False;
  Imp.Name := '';
  Imp.Ordinal := 0;

  M := ModuleOf(VA);
  if (M = nil) or M.IsImage then Exit;
  if not M.Parsed then ParseModule(M);
  if not M.HasExports then Exit;

  funcRVA := Cardinal(VA - M.Base);
  if not M.RVAToIndex.TryGetValue(funcRVA, idx) then Exit;

  ModIdx := M.Index;
  if M.NameByIndex[idx] <> '' then
  begin
    Imp.ByName := True;
    Imp.Name := M.NameByIndex[idx];
  end
  else
  begin
    Imp.ByName := False;
    Imp.Ordinal := Word(M.ExpBase + Cardinal(idx));
  end;
  Result := True;
end;

function TIATRebuilder.RebuildImports(const InDumpFile, OutFixedFile: string;
  StubStartRVA, StubEndRVA: Cardinal): TIATResult;
var
  R: TIATResult;
  f, blob, strbytes: TBytes;
  fs: TFileStream;
  lfanew, optOfs, secTab, ddBase: Cardinal;
  numSecs, sizeOpt, dllChar: Word;
  secAlign, fileAlign, sizeOfHeaders: Cardinal;
  i, scanEnd: NativeInt;
  V: Cardinal;
  cls, zeroRun: Integer;              // 0=other, 1=impptr, 2=zero
  runStart, runImp, runFirstImp, runLastImp: NativeInt;
  bestStart, bestEnd, stubStartSave, stubEndSave: NativeInt;
  bestImp, stubImpSave: Integer;
  iatStart, iatEnd: Cardinal;
  groups: TList<TImpGroup>;
  curEntries: TList<TImp>;
  g: TImpGroup;
  curMod: Integer;
  grpStart: Cardinal;
  mIdx: Integer;
  imp: TImp;
  descCount, descSize, iltTotal, strBase, blobSize: Cardinal;
  runIlt: Cardinal;
  gi, k: Integer;
  dllOff: TDictionary<Integer, Cardinal>;
  ibnOff: TDictionary<AnsiString, Cardinal>;
  baseRVA, newSecVA, rawSize: Cardinal;
  off, p: Cardinal;
  nm: AnsiString;
  o: Cardinal;

  procedure CloseGroup;
  begin
    if (curMod <> -1) and (curEntries.Count > 0) then
    begin
      g.ModIndex := curMod;
      g.StartRVA := grpStart;
      g.Entries := curEntries.ToArray;
      g.ILTOffset := 0;
      groups.Add(g);
    end;
    curEntries.Clear;
    curMod := -1;
  end;

  procedure ScanRange(SkipStub: Boolean);
  begin
    bestStart := -1; bestEnd := -1; bestImp := 0;
    runStart := -1; runImp := 0; runFirstImp := -1; runLastImp := -1;
    zeroRun := 0;

    i := sizeOfHeaders;
    while i <= scanEnd do
    begin
      if SkipStub and (StubEndRVA > StubStartRVA) and
         (Cardinal(i) >= StubStartRVA) and (Cardinal(i) < StubEndRVA) then
        cls := 0
      else
      begin
        V := PCardinal(@f[i])^;
        if V = 0 then
        begin
          Inc(zeroRun);
          if (runStart >= 0) and (zeroRun <= MAX_ZERO_GAP) then
            cls := 2
          else
            cls := 0;
        end
        else
        begin
          zeroRun := 0;
          if (ModuleOf(V) <> nil) and (not ModuleOf(V).IsImage) then
            cls := 1
          else
            cls := 0;
        end;
      end;

      if cls = 0 then
      begin
        if (runStart >= 0) and (runImp >= MIN_IMPORTS) and (runImp > bestImp) then
        begin
          bestImp := runImp; bestStart := runFirstImp; bestEnd := runLastImp + 4;
        end;
        runStart := -1; runImp := 0; runFirstImp := -1; runLastImp := -1;
        zeroRun := 0;
      end
      else
      begin
        if runStart < 0 then runStart := i;
        if cls = 1 then
        begin
          Inc(runImp);
          if runFirstImp < 0 then runFirstImp := i;
          runLastImp := i;
        end;
      end;
      Inc(i, 4);
    end;
    if (runStart >= 0) and (runImp >= MIN_IMPORTS) and (runImp > bestImp) then
    begin
      bestImp := runImp; bestStart := runFirstImp; bestEnd := runLastImp + 4;
    end;
  end;

begin
  R := Default(TIATResult);
  R.OutFile := OutFixedFile;

  // ---- load dump + parse headers ----
  try
    fs := TFileStream.Create(InDumpFile, fmOpenRead or fmShareDenyWrite);
    try
      SetLength(f, fs.Size);
      if fs.Size > 0 then fs.ReadBuffer(f[0], fs.Size);
    finally
      fs.Free;
    end;
  except
    on E: Exception do
    begin
      R.Message := 'Cannot read dump: ' + E.Message;
      Exit(R);
    end;
  end;

  if (Length(f) < 64) or (PWord(@f[0])^ <> $5A4D) then
  begin
    R.Message := 'Dump is not a PE.';
    Exit(R);
  end;
  lfanew := PCardinal(@f[$3C])^;
  if UInt64(lfanew) + 24 + 96 + (DDIR_IAT + 1) * 8 > UInt64(Length(f)) then
  begin
    R.Message := 'Dump headers are truncated; cannot rebuild.';
    Exit(R);
  end;
  optOfs := lfanew + 24;
  if PWord(@f[optOfs])^ <> $10B then
  begin
    R.Message := 'Dump is not PE32 (32-bit).';
    Exit(R);
  end;
  FImageBase    := PCardinal(@f[optOfs + 28])^;
  FSizeOfImage  := PCardinal(@f[optOfs + 56])^;
  sizeOfHeaders := PCardinal(@f[optOfs + 60])^;
  secAlign      := PCardinal(@f[optOfs + 32])^;
  fileAlign     := PCardinal(@f[optOfs + 36])^;
  numSecs       := PWord(@f[lfanew + 6])^;
  sizeOpt       := PWord(@f[lfanew + 20])^;
  secTab        := optOfs + sizeOpt;
  ddBase        := optOfs + 96;

  if UInt64(secTab) + UInt64(numSecs) * 40 > UInt64(Length(f)) then
  begin
    R.Message := 'Dump headers are truncated; cannot rebuild.';
    Exit(R);
  end;

  if (fileAlign = 0) or ((fileAlign and (fileAlign - 1)) <> 0) or
     (secAlign = 0)  or ((secAlign and (secAlign - 1)) <> 0) or
     (fileAlign > $10000) or (secAlign < fileAlign) or
     (FSizeOfImage > $40000000) then
  begin
    R.Message := 'Dump has invalid alignment/size fields; cannot rebuild.';
    Exit(R);
  end;

  if sizeOfHeaders > Cardinal(Length(f)) then
    sizeOfHeaders := Cardinal(Length(f));

  EnumModules;
  if FMods.Count = 0 then
  begin
    R.Message := 'Could not enumerate target modules (is it still alive at OEP?).';
    Exit(R);
  end;

  // ---- scan for the IAT (best run of module pointers) ----
  scanEnd := Length(f) - 4;
  if NativeInt(FSizeOfImage) - 4 < scanEnd then scanEnd := NativeInt(FSizeOfImage) - 4;

  ScanRange(False);
  if (bestStart >= 0) and (bestImp <= 5) and (StubEndRVA > StubStartRVA) and
     (Cardinal(bestStart) >= StubStartRVA) and (Cardinal(bestStart) < StubEndRVA) then
  begin
    stubStartSave := bestStart;
    stubEndSave := bestEnd;
    stubImpSave := bestImp;
    ScanRange(True);
    if bestStart < 0 then
    begin
      bestStart := stubStartSave; bestEnd := stubEndSave; bestImp := stubImpSave;
    end;
  end;

  if bestStart < 0 then
  begin
    R.Message := 'No IAT found (no run of >= ' + IntToStr(MIN_IMPORTS) + ' import pointers).';
    Exit(R);
  end;

  iatStart := Cardinal(bestStart);
  iatEnd := Cardinal(bestEnd);
  R.IATStartRVA := iatStart;
  R.IATSize := iatEnd - iatStart;
  Log(Format('IAT at RVA $%x .. $%x (%d pointers)', [iatStart, iatEnd, bestImp]));

  // ---- walk the IAT, resolve, group by module ----
  groups := TList<TImpGroup>.Create;
  curEntries := TList<TImp>.Create;
  curMod := -1; grpStart := 0;
  try
    i := iatStart;
    while i <= NativeInt(iatEnd) - 4 do
    begin
      V := PCardinal(@f[i])^;
      if V = 0 then
        CloseGroup
      else if Resolve(V, mIdx, imp) then
      begin
        if curMod = -1 then
        begin
          curMod := mIdx; grpStart := Cardinal(i);
        end
        else if mIdx <> curMod then
        begin
          CloseGroup;
          curMod := mIdx; grpStart := Cardinal(i);
        end;
        curEntries.Add(imp);
        Inc(R.Imports);
      end
      else
      begin
        Inc(R.Unresolved);
        CloseGroup;
      end;
      Inc(i, 4);
    end;
    CloseGroup;

    R.Descriptors := groups.Count;
    if groups.Count = 0 then
    begin
      R.Message := 'IAT found but nothing resolved to known exports.';
      Exit(R);
    end;

    descCount := groups.Count;
    descSize := (descCount + 1) * 20;

    runIlt := descSize;
    for gi := 0 to groups.Count - 1 do
    begin
      g := groups[gi];
      g.ILTOffset := runIlt;
      groups[gi] := g;
      runIlt := runIlt + Cardinal(Length(g.Entries) + 1) * 4;
    end;
    iltTotal := runIlt - descSize;
    strBase := descSize + iltTotal;

    dllOff := TDictionary<Integer, Cardinal>.Create;
    ibnOff := TDictionary<AnsiString, Cardinal>.Create;
    SetLength(strbytes, 0);
    try
      for gi := 0 to groups.Count - 1 do
      begin
        g := groups[gi];
        if not dllOff.ContainsKey(g.ModIndex) then
        begin
          nm := AnsiString(FMods[g.ModIndex].Name);
          o := Cardinal(Length(strbytes));
          dllOff.Add(g.ModIndex, o);
          SetLength(strbytes, Length(strbytes) + Length(nm) + 1);
          if Length(nm) > 0 then Move(nm[1], strbytes[o], Length(nm));
          strbytes[o + Cardinal(Length(nm))] := 0;
        end;
        for k := 0 to High(g.Entries) do
          if g.Entries[k].ByName and (not ibnOff.ContainsKey(g.Entries[k].Name)) then
          begin
            if Odd(Length(strbytes)) then
              SetLength(strbytes, Length(strbytes) + 1);
            nm := g.Entries[k].Name;
            o := Cardinal(Length(strbytes));
            ibnOff.Add(nm, o);
            SetLength(strbytes, Length(strbytes) + 2 + Length(nm) + 1);
            PWord(@strbytes[o])^ := 0;
            if Length(nm) > 0 then Move(nm[1], strbytes[o + 2], Length(nm));
            strbytes[o + 2 + Cardinal(Length(nm))] := 0;
          end;
      end;

      blobSize := strBase + Cardinal(Length(strbytes));

      newSecVA := Align(Cardinal(Length(f)), secAlign);
      if newSecVA < Align(FSizeOfImage, secAlign) then
        newSecVA := Align(FSizeOfImage, secAlign);
      baseRVA := newSecVA;

      if secTab + (Cardinal(numSecs) + 1) * 40 > sizeOfHeaders then
      begin
        R.Message := 'No room in PE header for an extra section.';
        Exit(R);
      end;

      SetLength(blob, blobSize);
      FillChar(blob[0], blobSize, 0);
      for gi := 0 to groups.Count - 1 do
      begin
        g := groups[gi];
        off := Cardinal(gi) * 20;
        PCardinal(@blob[off + 0])^  := baseRVA + g.ILTOffset;                 // OriginalFirstThunk
        PCardinal(@blob[off + 12])^ := baseRVA + strBase + dllOff[g.ModIndex]; // Name
        PCardinal(@blob[off + 16])^ := g.StartRVA;                            // FirstThunk (existing IAT)
      end;
      for gi := 0 to groups.Count - 1 do
      begin
        g := groups[gi];
        p := g.ILTOffset;
        for k := 0 to High(g.Entries) do
        begin
          if g.Entries[k].ByName then
            PCardinal(@blob[p])^ := baseRVA + strBase + ibnOff[g.Entries[k].Name]
          else
            PCardinal(@blob[p])^ := IMPORT_BY_ORDINAL or Cardinal(g.Entries[k].Ordinal);
          Inc(p, 4);
        end;
        PCardinal(@blob[p])^ := 0;
      end;
      if Length(strbytes) > 0 then
        Move(strbytes[0], blob[strBase], Length(strbytes));

      rawSize := Align(blobSize, fileAlign);
      SetLength(f, newSecVA + rawSize);
      Move(blob[0], f[newSecVA], blobSize);

      off := secTab + Cardinal(numSecs) * 40;
      FillChar(f[off], 40, 0);
      nm := '.ncimp';
      Move(nm[1], f[off], Length(nm));
      PCardinal(@f[off + 8])^  := blobSize;
      PCardinal(@f[off + 12])^ := newSecVA;
      PCardinal(@f[off + 16])^ := rawSize;
      PCardinal(@f[off + 20])^ := newSecVA;
      PCardinal(@f[off + 36])^ := $C0000040;

      PWord(@f[lfanew + 6])^      := numSecs + 1;
      PCardinal(@f[optOfs + 56])^ := newSecVA + Align(blobSize, secAlign);
      // Clear DYNAMIC_BASE and stale base relocations from the packed image
      dllChar := PWord(@f[optOfs + 70])^;
      PWord(@f[optOfs + 70])^ := dllChar and not Word(DLL_CHAR_DYNAMIC_BASE);
      PCardinal(@f[ddBase + DDIR_IMPORT * 8])^        := baseRVA;
      PCardinal(@f[ddBase + DDIR_IMPORT * 8 + 4])^    := descSize;
      PCardinal(@f[ddBase + DDIR_BASERELOC * 8])^     := 0;
      PCardinal(@f[ddBase + DDIR_BASERELOC * 8 + 4])^ := 0;
      PCardinal(@f[ddBase + DDIR_IAT * 8])^           := iatStart;
      PCardinal(@f[ddBase + DDIR_IAT * 8 + 4])^       := iatEnd - iatStart;
      PCardinal(@f[ddBase + DDIR_BOUND * 8])^         := 0;
      PCardinal(@f[ddBase + DDIR_BOUND * 8 + 4])^     := 0;

      try
        fs := TFileStream.Create(OutFixedFile, fmCreate);
        try
          fs.WriteBuffer(f[0], Length(f));
        finally
          fs.Free;
        end;
        R.Success := True;
        R.Message := Format('Rebuilt %d imports across %d descriptors (%d unresolved).',
          [R.Imports, R.Descriptors, R.Unresolved]);
      except
        on E: Exception do
          R.Message := 'Write failed: ' + E.Message;
      end;
    finally
      dllOff.Free;
      ibnOff.Free;
    end;
  finally
    curEntries.Free;
    groups.Free;
  end;

  Result := R;
end;

end.
