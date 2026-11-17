program VMTScan;

{$APPTYPE CONSOLE}

{$IFDEF FPC}
  {$MODE DELPHI}
  {$H+}
{$ENDIF}

{
  Usage:  VMTScan <target.exe|dll>

  Lists the Delphi classes recovered from a PE (name, instance size, parent).
  Output is accessible plain text; exit code reflects the outcome.
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
