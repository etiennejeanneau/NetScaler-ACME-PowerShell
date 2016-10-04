###############################################################################
### Let's Encrypt (www.letsencrypt.org) automation for NetScaler certificates
### Versions:
### =========
### 			0.1		Initial version
###				0.2		Using PEM certificates only and removing the need for openssl
###				0.3		Code Cleanup for initial release
###
###############################################################################


################################## VARIABLES ##################################
#
# Fill in the variables according to your environment!
#
# To encrypt your netscaler password
# In Powershell, run:
# -------------------------------------------------------------------------------------------
# > $password = read-host -prompt "Enter your Password"
# > $secure = ConvertTo-SecureString $password -force -asPlainText | ConvertFrom-SecureString
# > $secure | out-file c:\temp\securepassword.txt
# -------------------------------------------------------------------------------------------
# copy and paste the content pf c:\temp\securepassword.txt to the $nspwd variable below.
#

# NetScaler settings
$nsip = "192.168.1.100"
$nsuser = "nsroot"
$nspwd = "01000000d08c9ddf0115d1118c7a00c04fc297eb010000003ed0cdc24e930d49959f6f21c91703570000000002000000000003660000c000000010000000641080525e1898eec6a569c6924f7e7b0000000004800000a00000001000000004bfc103113fbc001e7676435ad178652800000045274e2e229d8a4ce03e1b658943073c6248238183047d8d334a39d13e619f14affdd5544b6fbaa81400000007b147e24feaa4943de4da7ebaf2355496727fbd"
$responderhtmlpagename = "letsencrypt"
$certkey="my_server_cert"

# ACMESharp settings i.e. letsencrypt
$email = "your_email@your_domain.tld"
$domainname = "your_domain.tld"
 
# prod: https://acme-v01.api.letsencrypt.org/
# staging: https://acme-staging.api.letsencrypt.org/
$ACMEURL = "https://acme-v01.api.letsencrypt.org/" 
$ACMEIdentifier = $domainname+"_Identifier"

# Certificate files location
$certpath = "c:\temp\automatic-cert-update\"

# Log filename
$logfile = $certpath+'log.txt'

# Dynamic CERT file naming
$date = Get-Date -UFormat %Y.%m.%d_%H.%M
$cert = $domainname +"_"+$date
$certpemfile = $certpath+$cert+"_PEM.crt"
$certpemfilename = $cert+"_PEM.crt"
$certpemkey = $certpath+$cert+"_PEM.key"
$certpemkeyname = $cert+"_PEM.key"
$certpemca = $certpath+$cert+"_CA_PEM.crt"
$certpemcaname = $cert+"_CA_PEM.crt"
$certcakey = $domainname+"_CA_PEM"

$certderfile = $certpath+$cert+"_DER.crt"
$certderfilename = $cert+"_DER.crt"
$certderkey = $certpath+$cert+"_DER.key"
$certderkeyname = $cert+"_DER.key"
$certderca = $certpath+$cert+"_CA_DER.crt"

# Path to the different used modules: Nitro API, ACMESharp and Write-Log
$nsmodule = ".\Netscaler_Nitro_API\Modules\NetScalerConfiguration\NetScalerConfiguration.psm1"
$ACMESharpmodule = ".\ACMESharp"
$writelogmodule = ".\write-log\Write-log.psm1"
#
#
###############################################################################

################################## CODE #######################################


# importing the log function and specifying the log file location
Import-Module $writelogmodule
$PSDefaultParameterValues=@{"Write-Log:Path"=$logfile}
Write-Log -Message '****** Automatic Cert Update - Start ******'

# Checking if the path specified already exists or not
if( -NOT (Test-Path $certpath)){
	New-Item $certpath -type directory
}  

# importing Nitro API PoSh module
Import-Module $nsmodule

# Importing ACMESharp PoSH module
Import-Module $ACMESharpmodule

# Decrypting $nspwd variable
$secure = ConvertTo-SecureString $nspwd
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $nsuser,$secure

# Connecting to NetScaler 
Set-NSMgmtProtocol -Protocol http
$session = Connect-NSAppliance -NSAddress $nsip -NSUserName $cred.GetNetworkCredential().username -NSPassword $cred.GetNetworkCredential().password

if($session){
	Write-Log -Message "Successfully connected to NetScaler @$nsip"
}else{
	Write-Log -Message "Error: Failed to connect to NetScaler @$nsip. Exiting..."
	Write-Log -Message '****** Automatic Cert Update - End ******'
	exit
}


# Checking if ACME vault exists 
$Vault = Get-ACMEVault
if($Vault -eq $null){
	Initialize-ACMEVault
	$Vault = Get-ACMEVault
	if($Vault -eq $null){
		Write-Log -Message "Error: ACME not initialized - Is it properly installed? Exiting..."
		Write-Log -Message '****** Automatic Cert Update - End ******'
		exit
	}else{
		Write-Log -Message 'ACME Vault initialized' 
	}
}else{
	Write-Log -Message 'ACME Vault already exists - reusing'  
}

# Setting the ACME environment to use: Prod or Staging
Set-ACMEVault -BaseUri $ACMEURL

# Checking if ACME registration exists
$ACMERegistration = Get-ACMERegistration
if($ACMERegistration -eq $null){
	New-ACMERegistration -Contacts mailto:$email -AcceptTos
	Write-Log -Message 'ACME Registration initialized' 
}else{
	Write-Log -Message 'ACME Registration already setup'
}

# Checking if ACME Identifier exists
$Identifier = Get-ACMEIdentifier | where-object {$_.Alias -eq $ACMEIdentifier}
if($Identifier -eq $null){
	New-ACMEIdentifier -Dns $domainname -Alias $ACMEIdentifier
	$Identifier = Get-ACMEIdentifier | where-object {$_.Alias -eq $ACMEIdentifier}
	Write-Log -Message "ACME Identifier $ACMEIdentifier initialized for domain: $domainname"
}else{
	Write-Log -Message "ACME Identifier $ACMEIdentifier already exists for domain: $domainname"
}


# Checking if we need to do the challenge (i.e. verify the domain belongs to us)
$challenge = Complete-ACMEChallenge $ACMEIdentifier -ChallengeType http-01 -Handler manual
$challengestatus = (Invoke-RestMethod -Uri $challenge.Uri).challenges | Where-Object {$_.type -eq "http-01"}
if($challengestatus.status -eq "pending"){
	
	# Upload new reponder HTML page with challengestatus.keyauthorization to the NetScaler
	Write-Log -Message "A http-01 challenge is pending for $ACMEIdentifier - Updating $responderhtmlpagename html page with KeyAuth: $keyauth"
	$Vault = Get-ACMEVault
	$keyauth = $Vault.Identifiers.authorization.Challenges.challenge.filecontent
	$keyencoded = [system.Text.Encoding]::ASCII.GetBytes($keyauth)
	$keyencoded = [System.Convert]::ToBase64String($keyencoded)
	Invoke-NSNitroRestApi -NSSession $session -OperationMethod DELETE -ResourceType systemfile -Arguments @{filename=$responderhtmlpagename;filelocation="/var/download/responder"}
	Invoke-NSNitroRestApi -NSSession $session -OperationMethod POST -ResourceType systemfile -Payload @{filename=$responderhtmlpagename;fileContent=$keyencoded;filelocation="/var/download/responder";fileencoding="BASE64"} -action add
		
	# Updating the responder HTML page
	Invoke-NSNitroRestApi -NSSession $session -OperationMethod POST -ResourceType responderhtmlpage -Payload @{name=$responderhtmlpagename} -action update
	Write-Log -Message "Responder HTML page $responderhtmlpagename has been updated"
	
	# submitting challenge
	Submit-ACMEChallenge $ACMEIdentifier -ChallengeType http-01
	Write-Log -Message "Submitting http-01 challenge for $ACMEIdentifier"
	
	# waiting for challenge to complete
	$challengecompleted = (Update-ACMEIdentifier $ACMEIdentifier -ChallengeType http-01).Challenges | Where-Object {$_.Type -eq "http-01"}
	while($challengecompleted.status -ne "valid"){
		start-sleep -s 5
		Submit-ACMEChallenge $ACMEIdentifier -ChallengeType http-01
		$challengecompleted = (Update-ACMEIdentifier $ACMEIdentifier -ChallengeType http-01).Challenges | Where-Object {$_.Type -eq "http-01"}
		Write-Log -Message "Challenge not completed yet, sleeping for 5s"
	}
	Write-Log -Message "Challenge completed!"
}	
	
# At this stage, the challenge should be either valid or failed... (i.e. not pending)
$challengestatus = (Invoke-RestMethod -Uri $challenge.Uri).challenges | Where-Object {$_.type -eq "http-01"}	
if($challengestatus.status -eq "valid"){

	Write-Log -Message "No http-01 challenge pending for $ACMEIdentifier, proceeding with certificate request"
	# request certs
	New-ACMECertificate $ACMEIdentifier -Generate -Alias $cert
	Submit-ACMECertificate $cert
	Write-Log -Message "Certificate $cert requested."
	$certcompleted = Update-ACMECertificate $cert
	while($certcompleted.IssuerSerialNumber -eq ""){
		start-sleep -s 5
		$certcompleted = Update-ACMECertificate $cert
		Write-Log -Message "Certificate request still pending, sleeping for 5s"
	}
	Write-Log -Message "Certificate request completed! Trying to download..."
	
	# Downloading PEM cert
	Get-ACMECertificate $cert -ExportCertificatePEM $certpemfile

	# Downloading PEM cert key
	Get-ACMECertificate $cert -ExportKeyPEM $certpemkey

	# Downloading PEM CA chain cert
	Get-ACMECertificate $cert -ExportIssuerPEM $certpemca

}else {
	Write-Log -Message "Error: No valid or pending http-01 challenge for $ACMEIdentifier. Exiting..."
	Write-Log -Message '****** Automatic Cert Update - End ******'
	exit
}

# Upload the certs and update certkey on NetScaler
if((Test-path $certpemfile) -AND (test-path $certpemkey) -AND (test-path $certpemca)){
	
	Write-Log -Message "Successfully downloaded certificate: $certpemfile"
	Write-Log -Message "Successfully downloaded private key: $certpemkey"
	Write-Log -Message "Successfully downloaded CA certificate (PEM): $certpemca"
	
	Write-Log -Message "Uploading the files to the NetScaler..."
	# reading the certificate private key to upload it via REST Nitro API 
	$certContent = Get-Content $certpemkey -Encoding "Byte"
	$certContentBase64 = [System.Convert]::ToBase64String($certContent)
	
	# uploading the key
	Invoke-NSNitroRestApi -NSSession $session -OperationMethod POST -ResourceType systemfile -Payload @{filename=$certpemkeyname;filelocation="/nsconfig/ssl";filecontent=$certContentBase64;fileencoding="BASE64"}
	# checking file upload
	$filecheck = Invoke-NSNitroRestApi -NSSession $session -OperationMethod GET -ResourceType systemfile -Arguments @{filename=$certpemkeyname;filelocation="/nsconfig/ssl"}
	if($filecheck){
		Write-Log -Message "$certpemkeyname successfully uploaded!"
	}else{
		Write-Log -Message "Error: failed to upload $certpemkeyname"
		Write-Log -Message '****** Automatic Cert Update - End ******'
		exit
	}
	
	# reading the certificate to upload it via REST Nitro API 
	$certContent = Get-Content $certpemfile -Encoding "Byte"
	$certContentBase64 = [System.Convert]::ToBase64String($certContent)
	# uploading the certificate
	Invoke-NSNitroRestApi -NSSession $session -OperationMethod POST -ResourceType systemfile -Payload @{filename=$certpemfilename;filelocation="/nsconfig/ssl";filecontent=$certContentBase64;fileencoding="BASE64"}
	# checking file upload
	$filecheck = Invoke-NSNitroRestApi -NSSession $session -OperationMethod GET -ResourceType systemfile -Arguments @{filename=$certpemfilename;filelocation="/nsconfig/ssl"}
	if($filecheck){
		Write-Log -Message "$certpemfilename successfully uploaded!"
	}else{
		Write-Log -Message "Error: failed to upload $certpemfilename"
		Write-Log -Message '****** Automatic Cert Update - End ******'
		exit
	}
		
	# checking if the certificate key already exists on the NetScaler
	try{
		$certkeyexists = Invoke-NSNitroRestApi -NSSession $session -OperationMethod GET -ResourceType sslcertkey -Arguments @{certkey=$certkey}
	}
	catch{
		$certkeyexists = $null
	}
	if($certkeyexists){
		Write-Log -Message "Trying to update existing certkey $certkey"
		Try{
			Invoke-NSNitroRestApi -NSSession $session -OperationMethod POST -ResourceType sslcertkey -Payload @{certkey=$certkey;cert=$certpemfilename;key=$certpemkeyname} -Action update
		}
		Catch{
			Write-Log -Message "Error: Something went wrong while updating existing certkey $certkey..."
			Write-Log -Message "Exiting..."
			Write-Log -Message '****** Automatic Cert Update - End ******'
			exit
		}
		#certificate check
		$certcheck = Invoke-NSNitroRestApi -NSSession $session -OperationMethod GET -ResourceType sslcertkey -Arguments @{certkey=$certkey}
		$validfrom = $certcheck.sslcertkey.clientcertnotbefore
		$validto = $certcheck.sslcertkey.clientcertnotafter
		$currcert = $certcheck.sslcertkey.cert
		$currkey = $certcheck.sslcertkey.key
		if($certcheck.sslcertkey.cert -eq $certpemfilename -AND $certcheck.sslcertkey.key -eq $certpemkeyname){
			Write-Log -Message "Certificate updated successfully!"
			Write-Log -Message "Current certificate uses $currcert and $currkey"
			Write-Log -Message "This certficate is valid from $validfrom to $validto"
			Write-Log -Message 'All done!'
			Write-Log -Message '****** Automatic Cert Update - End ******'
			exit
		}else{
			Write-Log -Message "Error: Something went wrong..."
			Write-Log -Message "Current certificate uses $currcert and $currkey"
			Write-Log -Message "This certficate is valid from $validfrom to $validto"
			Write-Log -Message '****** Automatic Cert Update - End ******'
			exit
		}
	}else{
		#Uploading CA chain cert on NetScaler
		Write-Log -Message "Uploading the cert CA $certpemcaname..."
		$certContent = Get-Content $certpemca -Encoding "Byte"
		$certContentBase64 = [System.Convert]::ToBase64String($certContent)
		
		Invoke-NSNitroRestApi -NSSession $session -OperationMethod POST -ResourceType systemfile -Payload @{filename=$certpemcaname;filelocation="/nsconfig/ssl";filecontent=$certContentBase64;fileencoding="BASE64"}
		# checking file upload
		$filecheck = Invoke-NSNitroRestApi -NSSession $session -OperationMethod GET -ResourceType systemfile -Arguments @{filename=$certpemcaname;filelocation="/nsconfig/ssl"}
		if($filecheck){
			Write-Log -Message "$certpemcaname successfully uploaded!"
		}else{
			Write-Log -Message "Error: failed to upload $certpemcaname"
			exit
		}
		
		Write-Log -Message "Creating the certkey for CA $certcakey on NetScaler @$nsip"
		Try{
			Invoke-NSNitroRestApi -NSSession $session -OperationMethod POST -ResourceType sslcertkey -Payload @{certkey=$certcakey;cert=$certpemcaname} -Action add
		}
		Catch{
			Write-Log -Message 'Unable to add CA chain cert $certcakey'
			Write-Log -Message 'Exiting...'
			Write-Log -Message '****** Automatic Cert Update - End ******'
			exit
		}
		
		Write-Log -Message "Creating the certkey $certkey on NetScaler @$nsip"
		Try{
			Invoke-NSNitroRestApi -NSSession $session -OperationMethod POST -ResourceType sslcertkey -Payload @{certkey=$certkey;cert=$certpemfilename;key=$certpemkeyname} -Action add
		}
		Catch{
			Write-Log -Message 'Unable to create certkey $certkey'
			Write-Log -Message 'Exiting...'
			Write-Log -Message '****** Automatic Cert Update - End ******'
			exit
		}
		
		Write-Log -Message "Binding certkey $certkey with cert CA $certcakey"
		Invoke-NSNitroRestApi -NSSession $session -OperationMethod POST -ResourceType sslcertkey -Payload @{certkey=$certkey;linkcertkeyname=$certcakey} -Action link
		
		#certificate check
		$certcheck = Invoke-NSNitroRestApi -NSSession $session -OperationMethod GET -ResourceType sslcertkey -Arguments @{certkey=$certkey}
		$validfrom = $certcheck.sslcertkey.clientcertnotbefore
		$validto = $certcheck.sslcertkey.clientcertnotafter
		$currcert = $certcheck.sslcertkey.cert
		$currkey = $certcheck.sslcertkey.key
		if($certcheck.sslcertkey.cert -eq $certpemfilename -AND $certcheck.sslcertkey.key -eq $certpemkeyname){
			Write-Log -Message "Certificate updated successfully!"
			Write-Log -Message "Current certificate uses $currcert and $currkey"
			Write-Log -Message "This certficate is valid from $validfrom to $validto"
		}else{
			Write-Log -Message "Error: Something went wrong..."
			Write-Log -Message "Current certificate uses $currcert and $currkey"
			Write-Log -Message "This certficate is valid from $validfrom to $validto"
		}
		Write-Log -Message '****** Automatic Cert Update - End ******'
		exit
	}
}else{
	Write-Log -Message "Error: Unable to find PEM certs. Exiting..."
	Write-Log -Message '****** Automatic Cert Update - End ******'
	exit
}



