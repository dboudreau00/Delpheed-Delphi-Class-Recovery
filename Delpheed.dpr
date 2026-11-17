program Delpheed;

{$APPTYPE CONSOLE}

{$IFDEF FPC}
  {$MODE DELPHI}
  {$H+}
{$ENDIF}

{
  Delpheed - one-shot pipeline over a Delphi PE (32-bit and 64-bit targets).

    Usage:  Delpheed <target.exe> [/aad]

      /aad   hide the debugger from the target during unpacking

  Builds 32-bit (unpacks 32-bit targets in-process; delegates 64-bit packed
  targets to companion OEPScan64.exe). See Delpheed64.dpr for the native
  64-bit build. Unpacking runs the target's stub - untrusted samples in a VM only.
}

uses
  SysUtils,
  uConsoleOut in 'uConsoleOut.pas',
  uPEFile in 'uPEFile.pas',
  uPackDetect in 'uPackDetect.pas',
  uDelphiVMT in 'uDelphiVMT.pas',
  uOEPFinder in 'uOEPFinder.pas',
  uUnpacker in 'uUnpacker.pas',
  uDelpheedMain in 'uDelpheedMain.pas';

begin
  RunDelpheed;
end.
