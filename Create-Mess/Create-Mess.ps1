<#
    Create-Mess
    .SYNOPSIS
    This script generates a ton of random files

    .DESCRIPTION
    This script generates a bunch of random files and folders in a specified directory.

    .PARAMETER ParentFolder
    The folder where the files will be created.  Default is .\

    .PARAMETER FilesToCreate
    The number of files to create.  Default is 100k

    .PARAMETER FolderRandomizationSeed
    This number is used to determine how often new folders are created and used.  For any
    file, you have roughly a 1/FolderRandomizationSeed chance that it will change directories.
    
    .PARAMETER MinSize
    The minimum size for any of the files created in bytes

    .PARAMETER MaxSize
    The maximum size for any file created in bytes

    .NOTES
    Created by Michael Melone, Principal Cybersecurity Consultant, Microsoft
#>
Function Create-Mess {
    param(
        [ValidateScript({Test-Path $_ -Type Container})]
        [string] $ParentFolder = ".\",
        [int] $FilesToCreate = 100000,
        [int] $FolderRandomizationSeed = 100,
        [int] $MinSize = 100,
        [int] $MaxSize = 25000
    )

    # Set the location to the specified folder
    Push-Location -StackName ParentStack -Path $ParentFolder

    # Set the current folder path
    $strCurrentFolder = (Resolve-Path ".\").path

    # Create a random number generator
    $rand = New-Object "System.Random" 
    
    # Loop until we hit FilesToCreate
    0..$FilesToCreate | % {
        # Get a random number
        $randomNumber = $rand.Next()

        # Determine if we will be changing folders
        if ($randomNumber % $FolderRandomizationSeed -eq 0)
        {
            # Ok, we will be changing folders.  Now determine if we go up or down a folder
            $goingUp = (($randomNumber / $FolderRandomizationSeed) % 2 -eq 0)

            if ($goingUp)
            {
                # Get a random folder name
                $newFolder = [system.IO.Path]::GetRandomFileName()

                # Ensure we won't hit the NTFS path length limit
                if ($strCurrentFolder.Length + ($newFolder.Length * 2) + 2 -ge 260)
                {
                    # Pop back one location before creating the folder to avoid exceeding the path limit
                    Pop-Location -StackName ChildStack
                }

                # Create it
                New-Item -Path ".\" -Name $newFolder -ItemType Directory | Out-Null

                # Push it
                Push-Location -StackName ChildStack $newFolder
            } else {
                # Try to pop the location.  If there is nothing on the stack it just stays put.
                Pop-Location -StackName ChildStack
            }

            # Update the current folder
            $strCurrentFolder = (Resolve-Path ".\").path
        }

        # Get a random filename
        $newFile = [system.IO.Path]::GetRandomFileName()
        $stream = [System.IO.FileStream]::new( "$strCurrentFolder\$newFile", [System.IO.FileMode]::Create )

        # Create some random junk to fill it with
        $bytesToCreate = $rand.Next($MinSize,$MaxSize)
        $bytes = [System.Byte[]]::new($bytesToCreate)
        $rand.NextBytes($bytes)

        # Write the bytes, close, and dispose
        $stream.Write($bytes,0,$bytes.Length)

        $stream.Close()
        $stream.Dispose()
    }

    # Return to where we started
    Pop-Location -StackName ParentStack
}

# This Sample Code is provided for the purpose of illustration only and is not intended to be used 
# in a production environment. THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" 
# WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED 
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. We grant You a nonexclusive, 
# royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code 
# form of the Sample Code, provided that You agree: (i) to not use Our name, logo, or trademarks to 
# market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright 
# notice on Your software product in which the Sample Code is embedded; and (iii) to indemnify, hold 
# harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys’ 
# fees, that arise or result from the use or distribution of the Sample Code.

# This sample script is not supported under any Microsoft standard support program or service. 
# The sample script is provided AS IS without warranty of any kind. Microsoft further disclaims 
# all implied warranties including, without limitation, any implied warranties of merchantability 
# or of fitness for a particular purpose. The entire risk arising out of the use or performance of 
# the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, 
# or anyone else involved in the creation, production, or delivery of the scripts be liable for any 
# damages whatsoever (including, without limitation, damages for loss of business profits, business 
# interruption, loss of business information, or other pecuniary loss) arising out of the use of or 
# inability to use the sample scripts or documentation, even if Microsoft has been advised of the 
# possibility of such damages 
