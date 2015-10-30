#requires -Version 3 -Modules ActiveDirectory
<#
  .Synopsis
  Cmdlet to test if an AD user is a member of a group
  .DESCRIPTION
  Cmdlet to test if an AD user is a member of a group.
  Written specifically to deal with groups containing 1500+ members
  .EXAMPLE
  PS C:\> Test-ADGroupMembership -UserName johndoe -GroupName 'Finance Users'
  True
  .OUTPUTS
  System.Boolean
  .NOTES
  Inspired by http://stackoverflow.com/a/33445473/712649
  Authored by Mathias R. Jessen (@IISResetMe), October 2015
#>
function Test-ADGroupMembership 
{
  [CmdletBinding()]
  [OutputType([System.Boolean])]
  Param(
    [Parameter(Mandatory=$true,Position=0)]
    [string]$UserName,
    [Parameter(Mandatory=$true,Position=1)]
    [string]$GroupName
  )

  # Fetch User
  try
  {
    $User = Get-ADUser -Identity $UserName -ErrorAction Stop
  }
  catch
  {
    throw $_
    return $false
  }

  # Use DirectorySearcher to retrieve ranged member attribute
  $GroupSearcher = '' -as [adsisearcher]
  $GroupSearcher.Filter = '(&(objectClass=group)(name={0}))' -f $GroupName
  $GroupSearcher.SearchScope = 'Subtree'
  $GroupSearcher.SearchRoot = '' -as [adsi]

  # AD reponds with at least 1500 values per multi-value attribute since Windows Server 2003
  $Start = 1
  $Range = 1500
  $GroupMembers = @()

  $HasMoreMembers = $false

  # Keep retrieving member values until we've got them all
  do
  {
    # Use range operator to "page" values
    # Ref: https://msdn.microsoft.com/en-us/library/aa367017(v=vs.85).aspx
    $RangedMember = 'member;range={0}-{1}' -f $Start, $($Start + $Range - 1)
    $null = $GroupSearcher.PropertiesToLoad.Add($RangedMember)

    try
    {
      # Retrieve group
      $Group = $GroupSearcher.FindOne()
    }
    catch
    {
      # return on failure
      Write-Error -Message $('Group "{0}" not found - {1}' -f $GroupName, $_.Exception.Message)
      return $false
    }

    # If we've reached the end of the member list, 
    # AD will return a property where the upper range
    # value is *, so it might not be the same property 
    # name we specified in PropertiesToLoad
    $ReturnedMember = @($Group.Properties.PropertyNames) -like 'member;*'

    # Add all members to the $GroupMembers variable
    foreach($member in $Group.Properties."$ReturnedMember") 
    { 
      # Test if user is in the member list
      if($member -eq $User.DistinguishedName)
      {
        return $true
      }
    }

    # If we've reached the end, exit the loop
    if($ReturnedMember -eq $RangedPropertyName)
    {
      $HasMoreMembers = $true
    }
  }
  while ($HasMoreMembers)

  # User wasn't found
  return $false
}
