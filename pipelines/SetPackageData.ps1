$gitHash = & git rev-parse HEAD
$gitBranch = $env:BUILD_SOURCEBRANCH
# The Substring(11) is because the git branch always starts with refs/heads/
$gitBranch = $gitBranch.replace("/", ".").SubString(11)
$vpackName = $env:BUILD_REPOSITORY_NAME + "." + $gitBranch
$vpackVersion = $env:NEW_ASSEMBLY_FILE_VERSION + "-Continuous"
$nugetVersion = $env:NEW_ASSEMBLY_FILE_VERSION
Write-Output "NUGET version is $nugetVersion"
Write-Output "Vpack name is $vpackName"
Write-Output "Vpack version is $vpackVersion"
echo "##vso[task.setvariable variable=VPACK_NAME]$vpackName"
echo "##vso[task.setvariable variable=VPACK_VERSION]$vpackVersion"
echo "##vso[task.setvariable variable=NUGET_VERSION]$nugetVersion"
echo "##vso[task.setvariable variable=GIT_COMMIT]$gitHash"