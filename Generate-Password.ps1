<#
.Synopsis
   PowerShell password generator
.DESCRIPTION
   PowerShell password generator, tuned to generate passwords that conform to Active Directory's default Password Complexity Requirements
.EXAMPLE
   PS C:\> Generate-Password -Length 24
   GHQ"e9=tkN$=Tpju8(F1*c&S
.EXAMPLE
   PS C:\> Generate-Password -SpecialChars:$false
   maTGjm94VA9SJqUv
.OUTPUTS
   String
.NOTES
   Author: Mathias R. Jessen, (@IISResetMe)
#>
function Generate-Password
{
    param(
        [ValidateRange(8,127)]
        [int]$Length = 16,
        [Switch]$SpecialChars=$true,
        [Switch]$ADComplexity=$true
    )
    
    [String]$pwd = ""

    # Strings containing alpha-numeric chars
    [String]$alpha    = "abcdefghijklmnopqrstuvwxyz"
    [String]$integers = "0123456789"
    [String]$specials = "~!@#$%^&*_-+=``|\(){}[]:;`"'<>,.?/"

    # Alpha-numeric char arrays
    [char[]]$lower    = $alpha.ToLowerInvariant()
    [char[]]$upper    = $alpha.ToUpperInvariant()
    [char[]]$numbers  = $integers
    [char[]]$nonalpha = $specials

    # Charset containing all of the alpha-numeric characters
    [char[]]$charSet = $lower + $upper + $numbers

    if($SpecialChars)
    {
        $charSet += $nonalpha
    }

    if($ADComplexity)
    {
        if($SpecialChars)
        {
            foreach($set in @($lower,$upper,$numbers,$nonalpha))
            {
                $pwd += (Get-Random -InputObject $set)
                $pwd += (Get-Random -InputObject $set)
            }
        }
        else
        {
            foreach($set in @($lower,$upper,$numbers))
            {
                $pwd += (Get-Random -InputObject $set)
                $pwd += (Get-Random -InputObject $set)
            }            
        }
    }

    while($pwd.Length -lt $Length)
    {
        $pwd += (Get-Random -InputObject $charSet)
    }

    $rand = New-Object System.Random 
    
    # Now do the shuffle
    1..10|ForEach-Object {
        $pwd = [String]::Join("",($pwd.ToCharArray()|Sort-Object {$rand.Next()}))
    }

    return $pwd
}
