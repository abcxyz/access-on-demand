# Release

**Access on Demand is not an official Google product.**

We leverage [goreleaser](https://goreleaser.com/) for SCM (GitHub) release, see
`.goreleaser.yaml`.

## New Release

-   Send a PR to update all dependencies For Go
```sh
go get -u && go mod tidy
```
-   Create a tag using `.github/workflows/create-tag.yml` and run the workflow
    with below inputs.

    -   tag name with format `v0.x.x`, using semantic versioning.
        -   If there are breaking changes, bump the major version.
        -   If there are new major features (but not breaking), bump the minor
            version.
        -   Nothing important, bump the patch version.
        -   Feel free to use suffixes -alpha, -beta and -rc as needed.
    -   annotated tag: `true`
    -   skip to use defaults for branch (repo default branch) and message (tag name).

-   The new created tag should trigger the release workflow which typically does
    two things:

    -   Integration test.
    -   Create a GitHub release with artifacts (e.g. code zip, binaries, etc.).
        Note: Goreleaser will automatically use the git change log to fill the
        release note.