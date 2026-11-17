unit uVMTScanMain;

{$IFDEF FPC}
  {$MODE DELPHI}
  {$H+}
{$ENDIF}

interface

procedure RunVMTScan;

implementation

uses
  SysUtils,
  uConsoleOut, uPEFile, uDelphiVMT;

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

procedure ScanFile(const FileName: string);
var
  PE: TPEFile;
  Sc: TDelphiVMTScanner;
  arr: TArray<TDelphiClass>;
  c: TDelphiClass;
  i: Integer;
  m: string;
begin
  PE := TPEFile.Create;
  try
    PE.LoadFromFile(FileName);
    if PE.Is64Bit then m := 'x64' else m := 'x86';

    COSection('PE summary');
    COField('File', FileName);
    COField('Machine', '$' + IntToHex(PE.Machine, 4) + ' (' + m + ')');
    COField('Image base', '$' + HexVA(PE.ImageBase, PE.Is64Bit));
    COField('Entry point RVA', '$' + IntToHex(PE.EntryPointRVA, 8));
    COField('Section count', IntToStr(Length(PE.Sections)));
    for i := 0 to High(PE.Sections) do
      COLine(Format('section %d: name=%s; rva=$%.8x; vsize=$%.8x; raw=$%.8x',
        [i, PE.Sections[i].Name, PE.Sections[i].VirtualAddress,
         PE.Sections[i].VirtualSize, PE.Sections[i].SizeOfRawData]));

    Sc := TDelphiVMTScanner.Create(PE);
    try
      Sc.Scan;
      arr := Sc.Classes;

      COSection('VMT scan');
      COField('Layout', Format('selfptr %d (%s)', [Sc.SelfPtrOffset, LayoutName(Sc.SelfPtrOffset)]));
      COField('Classes found', IntToStr(Length(arr)));

      if Length(arr) = 0 then
      begin
        CONote('No Delphi VMTs found: not a Delphi binary, packed, or rebased.');
        Exit;
      end;

      SortClassesByName(arr);

      COSection('Classes');
      for i := 0 to High(arr) do
      begin
        c := arr[i];
        if c.ParentName = '' then
          COLine(Format('class: %s; size=%d; parent=none (root TObject)',
            [c.Name, c.InstanceSize]))
        else if c.ParentName = '(external)' then
          COLine(Format('class: %s; size=%d; parent=external @ $%s',
            [c.Name, c.InstanceSize, HexVA(c.ParentVA, PE.Is64Bit)]))
        else
          COLine(Format('class: %s; size=%d; parent=%s',
            [c.Name, c.InstanceSize, c.ParentName]));
      end;
    finally
      Sc.Free;
    end;
  finally
    PE.Free;
  end;
end;

procedure RunVMTScan;
begin
  if ParamCount < 1 then
  begin
    COUsage(ChangeFileExt(ExtractFileName(ParamStr(0)), ''), '<target.exe|dll>',
      'List Delphi classes recovered from a PE.');
    Halt(EXIT_USAGE);
  end;
  try
    ScanFile(ParamStr(1));
    COOk('Done.');
    Halt(EXIT_OK);
  except
    on E: EInOutError do
    begin
      COErr('Cannot read input: ' + E.Message);
      Halt(EXIT_INPUT);
    end;
    on E: EPEFile do
    begin
      COErr('Invalid PE input: ' + E.Message);
      Halt(EXIT_INPUT);
    end;
    on E: Exception do
    begin
      COErr(E.ClassName + ': ' + E.Message);
      Halt(EXIT_PROCESSING);
    end;
  end;
end;

end.
