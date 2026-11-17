unit uDelpheedMain;

{$IFDEF FPC}
  {$MODE DELPHI}
  {$H+}
{$ENDIF}

{$IFNDEF FPC}
  {$WARN SYMBOL_PLATFORM OFF}
{$ENDIF}

interface

procedure RunDelpheed;

implementation

uses
  Windows, SysUtils, Classes,
  uConsoleOut, uPEFile, uPackDetect, uDelphiVMT
  {$IFDEF WIN64}
  , uOEPFinder64
  {$ELSE}
  , uOEPFinder, uUnpacker
  {$ENDIF};

function HexVA(V: UInt64; Is64: Boolean): string;
begin
  if Is64 then Result := IntToHex(Int64(V), 16) else Result := IntToHex(Int64(V), 8);
end;

function LayoutName(O: Integer): string;
begin
  case O of
    -76:  Result := 'Delphi 2-7 (x86)';
    -88:  Result := 'Delphi 2009+ (x86)';
    -100: Result := 'Delphi (x86, C++ ABI)';
    -176: Result := 'Delphi (x64, classic)';
    -200: Result := 'Delphi (x64, C++ ABI)';
  else
    Result := 'unknown';
  end;
end;

function FindCompanionTool(const ExeName: string): string;
var
  selfDir, cand: string;
begin
  selfDir := ExtractFilePath(ExpandFileName(ParamStr(0)));
  cand := selfDir + ExeName;
  if FileExists(cand) then Exit(cand);
  cand := IncludeTrailingPathDelimiter(GetCurrentDir) + ExeName;
  if FileExists(cand) then Exit(cand);
  Result := '';
end;

function RunHelperUnpacker(const ExeName, TargetPath, DumpPath: string;
  AAD: Boolean): Boolean;
var
  helperPath, cmd, acc, line: string;
  sa: TSecurityAttributes;
  hRead, hWrite: THandle;
  si: TStartupInfo;
  pi: TProcessInformation;
  buf: array[0..4095] of Byte;
  bytesRead: DWORD;
  exitCode: DWORD;
  chunk: AnsiString;
  p: Integer;

  procedure EmitLine(const S: string);
  var
    t: string;
  begin
    t := TrimRight(S);
    if t = '' then Exit;
    if Pos('ERROR:', t) = 1 then
      COErr(Trim(Copy(t, 7, MaxInt)))
    else if Pos('WARNING:', t) = 1 then
      COWarn(Trim(Copy(t, 9, MaxInt)))
    else
      COLine(t);
  end;

begin
  Result := False;
  helperPath := FindCompanionTool(ExeName);
  if helperPath = '' then
  begin
    COWarn('Companion unpacker "' + ExeName + '" not found next to ' +
      ExtractFileName(ParamStr(0)) + '.');
    Exit(False);
  end;

  cmd := '"' + helperPath + '" "' + TargetPath + '" "' + DumpPath + '" /iat';
  if AAD then cmd := cmd + ' /aad';
  UniqueString(cmd);

  FillChar(sa, SizeOf(sa), 0);
  sa.nLength := SizeOf(sa);
  sa.bInheritHandle := True;
  if not CreatePipe(hRead, hWrite, @sa, 0) then
  begin
    COWarn('Could not create pipe for ' + ExeName + '.');
    Exit(False);
  end;

  try
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);
    FillChar(si, SizeOf(si), 0);
    si.cb := SizeOf(si);
    si.dwFlags := STARTF_USESTDHANDLES;
    si.hStdInput := GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput := hWrite;
    si.hStdError := hWrite;
    FillChar(pi, SizeOf(pi), 0);

    if not CreateProcess(nil, PChar(cmd), nil, nil, True, 0, nil, nil, si, pi) then
    begin
      COWarn('Failed to launch ' + ExeName + ': ' + SysErrorMessage(GetLastError));
      CloseHandle(hWrite);
      Exit(False);
    end;

    CloseHandle(hWrite);
    hWrite := 0;
    try
      acc := '';
      while ReadFile(hRead, buf[0], SizeOf(buf), bytesRead, nil) and (bytesRead > 0) do
      begin
        SetString(chunk, PAnsiChar(@buf[0]), bytesRead);
        acc := acc + string(chunk);
        while True do
        begin
          p := Pos(#10, acc);
          if p = 0 then Break;
          line := Copy(acc, 1, p - 1);
          Delete(acc, 1, p);
          EmitLine(line);
        end;
      end;
      if acc <> '' then EmitLine(acc);

      WaitForSingleObject(pi.hProcess, INFINITE);
      exitCode := 1;
      GetExitCodeProcess(pi.hProcess, exitCode);
      Result := (exitCode = EXIT_OK) and FileExists(DumpPath);
    finally
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
    end;
  finally
    if hWrite <> 0 then CloseHandle(hWrite);
    CloseHandle(hRead);
  end;
end;

procedure ScanClasses(const Path: string);
var
  PE: TPEFile;
  Sc: TDelphiVMTScanner;
  arr: TArray<TDelphiClass>;
  c: TDelphiClass;
  i: Integer;
begin
  PE := TPEFile.Create;
  try
    PE.LoadFromFile(Path);
    Sc := TDelphiVMTScanner.Create(PE);
    try
      Sc.Scan;
      arr := Sc.Classes;

      COSection('Classes');
      COField('Source', Path);
      COField('Layout', Format('selfptr %d (%s)', [Sc.SelfPtrOffset, LayoutName(Sc.SelfPtrOffset)]));
      COField('Classes found', IntToStr(Length(arr)));
      if Length(arr) = 0 then
      begin
        CONote('No Delphi VMTs recovered from this image.');
        Exit;
      end;

      SortClassesByName(arr);

      for i := 0 to High(arr) do
      begin
        c := arr[i];
        if c.ParentName = '' then
          COLine(Format('class: %s; size=%d; parent=none (root TObject)', [c.Name, c.InstanceSize]))
        else if c.ParentName = '(external)' then
          COLine(Format('class: %s; size=%d; parent=external', [c.Name, c.InstanceSize]))
        else
          COLine(Format('class: %s; size=%d; parent=%s', [c.Name, c.InstanceSize, c.ParentName]));
      end;
    finally
      Sc.Free;
    end;
  finally
    PE.Free;
  end;
end;

procedure RunDelpheed;
var
  target, scanTarget, dump, bitness: string;
  PE: TPEFile;
  v: TPackVerdict;
  i: Integer;
  aad, targetIs64: Boolean;
  {$IFDEF WIN64}
  f64: TOEPFinder64;
  r64: TOEP64Result;
  {$ELSE}
  f32: TOEPFinder;
  r32: TOEPResult;
  u32: TGenericUnpacker;
  ur32: TUnpackResult;
  {$ENDIF}
begin
  if ParamCount < 1 then
  begin
    COUsage(ChangeFileExt(ExtractFileName(ParamStr(0)), ''), '<target.exe> [/aad]',
      'Detect packing, unpack if needed (32-bit or 64-bit), and list recovered Delphi classes.');
    Halt(EXIT_USAGE);
  end;

  target := ParamStr(1);
  aad := False;
  for i := 2 to ParamCount do
    if SameText(ParamStr(i), '/aad') then
      aad := True
    else
    begin
      COErr('Unrecognised argument: ' + ParamStr(i));
      Halt(EXIT_USAGE);
    end;

  scanTarget := target;

  PE := TPEFile.Create;
  try
    try
      PE.LoadFromFile(target);
    except
      on E: Exception do
      begin
        COErr('Cannot read input: ' + E.Message);
        Halt(EXIT_INPUT);
      end;
    end;

    targetIs64 := PE.Is64Bit;
    if targetIs64 then bitness := '64-bit (x64)' else bitness := '32-bit (x86)';

    COSection('PE summary');
    COField('File', target);
    COField('Bitness', bitness);
    COField('Image base', '$' + HexVA(PE.ImageBase, targetIs64));
    COField('Entry point RVA', '$' + IntToHex(PE.EntryPointRVA, 8));
    COField('Sections', IntToStr(Length(PE.Sections)));

    COSection('Packing analysis');
    v := AnalyzePacking(PE);
    COField('File entropy', Format('%.2f (of 8.0)', [v.FileEntropy]));
    if v.PackerName <> '' then
      COField('Packer', v.PackerName);
    COField('Likely packed', BoolToStr(v.LikelyPacked, True));
    COField('Confidence', IntToStr(v.Confidence) + '/100');
    for i := 0 to High(v.Reasons) do
      COLine('reason: ' + v.Reasons[i]);

    if v.LikelyPacked then
    begin
      dump := ChangeFileExt(target, '') + '_unpacked.exe';
      COSection('Unpacking');

      {$IFDEF WIN64}
      if targetIs64 then
      begin
        f64 := TOEPFinder64.Create(COLogger.Note);
        try
          f64.AntiAntiDebug := aad;
          f64.RebuildImports := True;
          r64 := f64.Find(target, dump);
        finally
          f64.Free;
        end;
        if r64.Success and (r64.DumpFile <> '') then
        begin
          COOk(r64.Message);
          scanTarget := r64.DumpFile;
        end
        else
          COWarn('Unpack did not complete (' + r64.Message + '); scanning original, which may find little.');
      end
      else
      begin
        CONote('Target is 32-bit; invoking companion OEPScan.exe ...');
        if RunHelperUnpacker('OEPScan.exe', target, dump, aad) then
        begin
          COOk('32-bit unpack completed.');
          scanTarget := dump;
        end
        else
          COWarn('32-bit unpack did not complete; scanning original, which may find little.');
      end;
      {$ELSE}
      if not targetIs64 then
      begin
        f32 := TOEPFinder.Create(COLogger.Note);
        try
          f32.AntiAntiDebug := aad;
          f32.RebuildImports := True;
          r32 := f32.Find(target, dump);
        finally
          f32.Free;
        end;
        if r32.Success and (r32.DumpFile <> '') then
        begin
          COOk(r32.Message);
          scanTarget := r32.DumpFile;
        end
        else
        begin
          CONote('Guard-page unpacker did not reach OEP (' + r32.Message + '); trying ESP trick...');
          u32 := TGenericUnpacker.Create(COLogger.Note);
          try
            ur32 := u32.Unpack(target, dump);
          finally
            u32.Free;
          end;
          if ur32.Success and (ur32.DumpFile <> '') then
          begin
            COOk(ur32.Message);
            scanTarget := ur32.DumpFile;
          end
          else
            COWarn('Unpack did not complete (' + ur32.Message + '); scanning original, which may find little.');
        end;
      end
      else
      begin
        CONote('Target is 64-bit; invoking companion OEPScan64.exe ...');
        if RunHelperUnpacker('OEPScan64.exe', target, dump, aad) then
        begin
          COOk('64-bit unpack completed.');
          scanTarget := dump;
        end
        else
          COWarn('64-bit unpack did not complete; scanning original, which may find little.');
      end;
      {$ENDIF}
    end;
  finally
    PE.Free;
  end;

  try
    ScanClasses(scanTarget);
    COOk('Analysis complete.');
    Halt(EXIT_OK);
  except
    on E: Exception do
    begin
      COErr(E.ClassName + ': ' + E.Message);
      Halt(EXIT_PROCESSING);
    end;
  end;
end;

end.
