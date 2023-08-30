# Release

**Access on Demand is not an official Google product.**

We leverage [goreleaser](https://goreleaser.com/) for SCM (GitHub) release, see
`.goreleaser.yaml`.

## New Release

-   Send a PR to update all dependencies For Go
```sh
go get -u && go mod tidy
```
-   Sync to main/HEAD
```sh
# Checkout to the main/HEAD
git checkout main
```
-   Create a tag using semantic versioning and then push the tag.
    -   If there are breaking changes, bump the major version
    -   If there are new major features (but not breaking), bump the minor
        version
    -   Nothing important, bump the patch version.
    -   Feel free to use suffixes -alpha, -beta and -rc as needed

```sh
REL_VER=v0.0.x
# Tag
git tag -f -a $REL_VER -m $REL_VER
# Push tag. This will trigger the release workflow.
git push origin $REL_VER
```

The new pushed tag should trigger the release workflow which typically does two
things:
- Integration test.
- Create a GitHub release with artifacts (e.g. code zip, binaries,
etc.). Note: Goreleaser will automatically use the git change log to fill the
release note.