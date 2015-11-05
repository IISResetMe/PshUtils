function ConvertTo-pKIFileTime
{
  param(
    [Parameter(Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
    [Alias('Seconds')]
    [long]$TotalSeconds
  )

  end {
    $NanoSeconds = $TotalSeconds * -10000000
  
    $pKIFileTime = [System.BitConverter]::GetBytes($NanoSeconds)
  
    return $pKIFileTime
  }
}
