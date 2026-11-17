program VMTScan64;

{$APPTYPE CONSOLE}

{$IFDEF FPC}
  {$MODE DELPHI}
  {$H+}
{$ENDIF}

{
  Usage:  VMTScan64 <target.exe|dll>

  64-bit native build of VMTScan (parses both 32-bit and 64-bit PEs).
}

uses
  SysUtils,
  uConsoleOut in 'uConsoleOut.pas',
  uPEFile in 'uPEFile.pas',
  uDelphiVMT in 'uDelphiVMT.pas',
  uVMTScanMain in 'uVMTScanMain.pas';

begin
  RunVMTScan;
end.
