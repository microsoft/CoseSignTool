---
ES.Build.CoseSignTool
---

# Contributing

*Welcome and thank you for your interest in contributing to ES.Build.CoseSignTool!*

This project has adopted the [Inner Source model](https://oe-documentation.azurewebsites.net/inner-source/index.html). Before contributing to this project, please review this document for policies and procedures which will ease the contribution and review process for everyone.

If you have questions, please contact the **[Core Build Team](CoreBuildTeam@service.microsoft.com)**.

## Issues and Feature Requests

Work items are tracked in [Issues](https://github.com/microsoft/CoseSignTool/issues). 

## Style Guidelines

Please respect the current style in the code.

## Testing
Certain features using the Windows certificate store will not work in non-Windows environments. If testing changes in a non-Windows environment, please test using `dotnet test --filter TestCategory!=WindowsOnly`

## Pull Request Process
1. Clone the [repo](https://github.com/microsoft/CoseSignTool).
1. Create a user or feature branch off of main.
1. Submit pull requests into main from your feature branch.
1. Ensure builds are still successful and tests, including any added or updated tests, pass prior to submitting the pull request.
1. Update any documentation, user and contributor, that is impacted by your changes.
1. Increase the version numbers in any examples and the [README.md](https://github.com/microsoft/CoseSignTool/blob/main/README.md) to the new version that this pull request would represent. The versioning scheme we use is [SemVer](http://semver.org/).
1. <should I add this?> Include your change description in `CHANGELOG.md` file as part of pull request.
1. You may merge the pull request in once you have the sign-off of 2 FTE, including at least one other developer.

## License Information

[MIT License](https://github.com/microsoft/CoseSignTool/blob/main/LICENSE)