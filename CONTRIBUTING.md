---
CoseSignTool
---

# Contributing

*Welcome and thank you for your interest in contributing to the CoseSignTool project!*

## Issues and Feature Requests

Work items are tracked in [Issues](https://github.com/microsoft/CoseSignTool/issues). 

## Style Guidelines

Please respect the current style in the code.
See [Stye.md](./STYLE.md) for details.

## Testing
Certain features using the Windows certificate store will not work in non-Windows environments. If testing changes in a non-Windows environment, please test using `dotnet test --filter TestCategory!=WindowsOnly`

## Pull Request Process
1. Clone the [repo](https://github.com/microsoft/CoseSignTool).
1. Create a user or feature branch off of main.
1. Submit pull requests into main from your feature branch.
1. Ensure builds are still successful and tests, including any added or updated tests, pass locally prior to submitting the pull request. The pull request automation will re-run the unit tests in Windows, Mac, and Linux environments.
1. Update any documentation, user and contributor, that is impacted by your changes.
1. Increase the version numbers in any examples and the [README.md](./README.md) to the new version that this pull request would represent. The versioning scheme we use is [SemVer](http://semver.org/).
1. <should I add this?> Include your change description in `CHANGELOG.md` file as part of pull request.
1. You may merge the pull request in once you have the sign-off of at least two Microsoft full-time employees, including at least one other developer.

## License Information

[MIT License](https://github.com/microsoft/CoseSignTool/blob/main/LICENSE)