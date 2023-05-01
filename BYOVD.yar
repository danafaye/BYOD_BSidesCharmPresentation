import "vt"
import "pe"

/*
Possible malicious driver with valid signature.
*/
rule pnp_coinstaller_insecure_driver
{
  strings:
      $IoCreateDevice = "IoCreateDevice" ascii wide
      $WdmlibIoCreateDeviceSecure = "WdmlibIoCreateDeviceSecure" ascii wide
      $IoValidateDeviceIoControlAccess = "IoValidateDeviceIoControlAccess" ascii wide
      $WdmlibIoValidateDeviceIoControlAccess = "WdmlibIoValidateDeviceIoControlAccess" ascii wide
      $IoCreateDeviceSecure = "IoCreateDeviceSecure" ascii wide
      $WdfPreDeviceInstallEx = "WdfPreDeviceInstall" ascii wide
  condition:
      ( $IoCreateDevice or $WdmlibIoCreateDeviceSecure) and
      not ($IoValidateDeviceIoControlAccess or 
           $WdmlibIoValidateDeviceIoControlAccess or
           $IoCreateDeviceSecure)
      and $WdfPreDeviceInstallEx
      and for all i in (0..pe.number_of_signatures - 1):
    	  (pe.signatures[i].valid_on(pe.timestamp))
      and not for any tag in vt.metadata.tags:
      	( tag == "corrupt" )  
      and for any tag in vt.metadata.tags:
        ( tag == "signed" )  
      and not for any tag in vt.metadata.tags:
        ( tag == "revoked-cert"  or tag == "invalid-signature")
}

/*
Possible malicious driver with valid signature.
*/
rule process_thread_manipulation_drivers_valid_sig
{
  strings:
      $IoCreateDevice = "IoCreateDevice" ascii wide
      $IoCreateDeviceSecure = "IoCreateDeviceSecure" ascii wide
      $WdmlibIoCreateDeviceSecure = "WdmlibIoCreateDeviceSecure" ascii wide
      $PsLookupProcessByProcessId = "PsLookupProcessByProcessId" ascii wide
      $ZwTerminateProcess = "ZwTerminateProcess" ascii wide
      $PsSuspendProcess = "PsSuspendProcess" ascii wide
      $PsSetCreateThreadNotifyRoutine = "PsSetCreateThreadNotifyRoutine" ascii wide
      $PsSetCreateProcessNotifyRoutineEx = "PsSetCreateProcessNotifyRoutine" ascii wide
      $IoValidateDeviceIoControlAccess = "IoValidateDeviceIoControlAccess" ascii wide
      $WdmlibIoValidateDeviceIoControlAccess = "WdmlibIoValidateDeviceIoControlAccess" ascii wide
  condition:
      ( $IoCreateDevice or $WdmlibIoCreateDeviceSecure) and
      $PsLookupProcessByProcessId and
      ( $ZwTerminateProcess or $PsSuspendProcess ) and
      $PsSetCreateThreadNotifyRoutine and 
      $PsSetCreateProcessNotifyRoutineEx and
      not ($IoValidateDeviceIoControlAccess or 
           $WdmlibIoValidateDeviceIoControlAccess or
           $IoCreateDeviceSecure)
      and for all i in (0..pe.number_of_signatures - 1):
    	  (pe.signatures[i].valid_on(pe.timestamp))

      and vt.metadata.new_file 
      and not for any tag in vt.metadata.tags:
      	( tag == "corrupt" )  
      and for any tag in vt.metadata.tags:
        ( tag == "signed" )  
      and not for any tag in vt.metadata.tags:
        ( tag == "revoked-cert"  or tag == "invalid-signature")
}

import "vt"

rule write_msr {

    /*
    $wr0-5
    mov ecx, [ebp+??]
    mov eax, [ebp+??]
    mov edx, [ebp+??]
    wrmsr

    $wr6-b
    mov ecx, imm32
    mov eax, imm32
    mov edx, imm32
    wrmsr

    */
    strings:
        $IoCreateDevice = "IoCreateDevice" ascii wide
        $IoCreateDeviceSecure = "IoCreateDeviceSecure" ascii wide
        $WdmlibIoCreateDeviceSecure = "WdmlibIoCreateDeviceSecure" ascii wide
        $wrmsr0 = {8B 4D ?? 8B 55 ?? 8B 45 ?? 0F 30}
        $wrmsr1 = {8B 4D ?? 8B 45 ?? 8B 55 ?? 0F 30}
        $wrmsr2 = {8B 55 ?? 8B 4D ?? 8B 45 ?? 0F 30}
        $wrmsr3 = {8B 55 ?? 8B 45 ?? 8B 4D ?? 0F 30}
        $wrmsr4 = {8B 45 ?? 8B 55 ?? 8B 4D ?? 0F 30}
        $wrmsr5 = {8B 45 ?? 8B 4D ?? 8B 55 ?? 0F 30}
        $wrmsr6 = {B8 ?? ?? ?? BA ?? ?? ?? B9 ?? ?? ?? 0F 30}
        $wrmsr7 = {B8 ?? ?? ?? B9 ?? ?? ?? BA ?? ?? ?? 0F 30}
        $wrmsr8 = {B9 ?? ?? ?? B8 ?? ?? ?? BA ?? ?? ?? 0F 30}
        $wrmsr9 = {B9 ?? ?? ?? BA ?? ?? ?? B8 ?? ?? ?? 0F 30}
        $wrmsr10 = {BA ?? ?? ?? B8 ?? ?? ?? B9 ?? ?? ?? 0F 30}
        $wrmsr11 = {BA ?? ?? ?? B9 ?? ?? ?? B8 ?? ?? ?? 0F 30}
        $DeviceIoControl = "DeviceIoControl" ascii wide
        $CreateFile = "CreateFile" ascii wide
    condition:
        ($IoCreateDevice or 
        $IoCreateDeviceSecure or 
        $WdmlibIoCreateDeviceSecure) and
        (1 of ($wr*)) and
        $DeviceIoControl and
        $CreateFile and
        filesize < 10MB and not
        for any tag in vt.metadata.tags:
            ( tag == "corrupt" )  
}
