# SignServer contributing guidelines <!-- omit in toc -->

Thank you for contributing to SignServer!

In this guide, you get an overview of the contribution workflow from starting a discussion or opening an issue, to creating, reviewing, and merging a pull request.

For an overview of the project, see [README](README.md). 

### Start a discussion
If you have a question or problem, you can [search in discussions](../../discussions), if someone has already found a solution to your problem. 

Or you can [start a new discussion](../../discussions/new/choose) and ask your question. 

### Create an issue

If you find a problem with SignServer, [search if an issue already exists](../../issues).

If a related discussion or issue doesn't exist, you can [open a new issue](../../issues/new). An issue can be converted into a discussion if regarded as one.

### Contribute to the code

#### Create a pull request

You are welcome to send patches, under the LGPLv2.1+ license, as pull requests. For more information, see [Creating a pull request](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request). For minor updates, you can instead choose to create an issue with short snippets of code. See above.

* Create a JUnit test case for your change, it may be a simple addition to an existing test. If you do not know how to do this, ask us and we will help you. 
* If you run into any merge issues, check out this [git tutorial](https://github.com/skills/resolve-merge-conflicts) to help you resolve merge conflicts and other issues.

For instructions on building and developing SignServer, refer to the SignServer documentation on [Developer Reference](https://doc.primekey.com/signserver/signserver-reference/developer-reference).

#### Self-review

Don't forget to self-review. Please follow these simple guidelines:
* Keep the patch limited, only change the parts related to your patch. 
* Do not change other lines, such as whitespace, adding line breaks to Java doc, etc. It will make it very hard for us to review the patch.

#### Your pull request is merged

For acceptance, pull requests need to meet specific quality criteria, including tests for anything substantial. Someone on the SignServer core team will review the pull request when there is time, and let you know if something is missing or suggest improvements. If it is a useful and generic feature it will be integrated in SignServer to be available in a later release.

For substantial, non-trivial contributions, you will be asked to sign a contributor assignment agreement. Optionally, you can also have your name and contact information listed on the [Contributors](https://www.signserver.org/contributors/) page. 
