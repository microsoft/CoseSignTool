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
All unit tests in the repo must pass in Windows, Linux, and MacOS environments to ensure compatitility.

## Pull Request Process
_Note: There was a bug in the pull request process which caused Github to lose track of running workflows when the CreateChangelog job completes. The work around is to close and re-open the pull request on the pull request page <span>(https<nolink>://github.com/microsoft/CoseSignTool/pull/[pull-request-number])</span> We beleive this is fixed as of version 1.1.1-pre1 so please log an issue if it reappears._
1. Clone the [repo](https://github.com/microsoft/CoseSignTool).
1. Create a user or feature branch off of main. Do not use the keyword "hotfix" or "develope" in your branch names as these will trigger incorrect release behavior.
1. Make your changes, including adding or updating unit tests to ensure your changes work as intended.
1. Make sure the solution still builds and all unit tests still pass locally.
1. Update any documentation, user and contributor, that is impacted by your changes. See [CoseSignTool.md](./CoseSignTool.md) for the CoseSignTool project, [CoseHandler.md](./CoseHandler.md) for the CoseHandler project, and [Advanced.md](./Advanced.md) for the CoseSign1 projects.
1. Push your changes to origin and create a pull request into main from your branch. The pull request automation will re-run the unit tests in Windows, MacOS, and Linux environments.
1. Fix any build or test failures or CodeQL warnings caught by the pull request automation and push the fixes to your branch.
1. Address any code review comments.
1. You may merge the pull request in once you have the sign-off of at least two Microsoft full-time employees, including at least one other developer.
Do not modify CHANGELOG.md, as it is auto-generated.

## Releases
Releases are created automatically on completion of a pull request into main, and have the pre-release flag set. Official releases are created manually by the repo owners and do not use the pre-release flag.
In both cases, the built binaries and other assets for the release are made available in .zip files.

### Creating a Manual Release (repo owners)
1. From the [Releases page](https://github.com/microsoft/CoseSignTool/releases), click _Draft a new release_
1. Click _Choose a tag_ and create a new, semantically versioned tag in the format v[Major.Minor.Patch], such as v0.3.2. In general, a Patch release represents a new feature or a group of important bug fixes. A Minor release represents a coherent set of features, and a Major release is either a significant overhaul of the product or a stabilization point in the code after a significant number of Minor releases.
1. Set _Release title_ to "Release _tag_"
1. Click _Generate release notes_
1. Edit the generated release notes to include a brief summary at the top, in user focused language, of what features were added and any important bugs that were fixed.
1. Make sure the _Set as a pre-release_ box is _not_ checked.
1. Click _Publish release_.

## License Information
[MIT License](https://github.com/microsoft/CoseSignTool/blob/main/LICENSE)