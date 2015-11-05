function ConvertFrom-pKIFileTime
{
    param(
        [Parameter(Mandatory=$true,
            ValueFromPipeline=$true,
            Position=0)]
        [byte[]]$pKIFileTime
    )

    begin {
        [byte[]]$ftBytes = @()
    }

    process {
        foreach($byte in $pKIFileTime){
            $ftBytes += $byte
        }
    }

    end{
        $Seconds = [System.BitConverter]::ToInt64($ftBytes,0) * -.0000001

        return New-TimeSpan -Seconds $Seconds
    }
}
