program Delpheed64;

{$APPTYPE CONSOLE}

{$IFDEF FPC}
  {$MODE DELPHI}
  {$H+}
{$ENDIF}

{
  Delpheed64 - 64-bit native one-shot pipeline over a Delphi PE (32-bit and
  64-bit targets).

    Usage:  Delpheed64 <target.exe> [/aad]

      /aad   hide the debugger from the target during unpacking

  Builds 64-bit (unpacks 64-bit targets in-process; delegates 32-bit packed
  targets to companion OEPScan.exe). Unpacking runs the target's stub -
  untrusted samples in a VM only.
}

uses
  SysUtils,
  uConsoleOut in 'uConsoleOut.pas',
  uPEFile in 'uPEFile.pas',
  uPackDetect in 'uPackDetect.pas',
  uDelphiVMT in 'uDelphiVMT.pas',
  uOEPFinder64 in 'uOEPFinder64.pas',
  uDelpheedMain in 'uDelpheedMain.pas';

begin
  RunDelpheed;
end.
