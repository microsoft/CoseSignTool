# Style and Architecture Guildelines
CoseSignTool and the accompanying libraries are used in security-critical, performance-critical production environments and must maintain the highest standards in both these areas. We also believe it is important to make the tools and API easy for developers to use and maintain, so the API surface must remain clean and intuitive, and code should be textbook-quality in terms of readability.

## Security
### Signing the signing tools
This repo includes a public key file for strongname signing. If you download from GitHub or build from source, your assemblies will be open source strongname signed, which is sufficient for other strongname signed assemblies to be able to call into them, but will not pass direct signing validation. Users are welcome to sign their own builds, or to turn off strongname signing by editing their local copies of the project files before building.
Microsoft will release fully Authenticode-signed versions of the tool and libraries soon, probably through NuGet.org and existing Software Development Kits.

### Secrets
Do not add certificates, Azure secrets, private keys (including strongname private keys), or any other private or potentially sensitive information to the repo. If a secret is added even temporarily, it will be discoverable long after deletion and must be invalidated immediately. If you need certificates for testing, use the functions in CoseSign1.Tests.Common.TestCertificateUtils to create them, or add your own functions to create custom certificates if those do not meet your needs.

### Certificate store access
The CoseHandler class has a static LookupCertificate method to find installed certificates. If you modify this method or add other methods that access the local certificate store, write unit tests to ensure that your changes are compatible across Windows, Linux, and MacOS operating systems. Your tests will run on all three platforms when you create a pull request.

When writing unit tests that touch store functions, try to avoid making any changes to the certificate stores on the local machine.
* Consider using Moq for unit tests where certificate store behaviors are not relevant to the test.
* When certificate store behaviors are relevant but it doens't matter which certificate you use, you can check what certificates are locally installed and test store lookup functions on those.
* If you need a specific certificate installed, create a custom store by adding the certificate to a store with an non-standard StoreName value such as "CoseSignToolTestStore", and then removing it during cleanup
* Alternatively, consider making the test an integration test that only runs manually.

## Performance
As mentioned, CoseSignTool is a performance-critical application. In addition to the conventional wisdom about practices such as reducing file reads, the development team did some benchmarking to compare common code paths.

### File and network I/O
As with any program, the standard pricipals of I/O performance apply here. Interact with the file system and the network as little as possible, and try to group your reads and writes into as few discreet interactions as possible. In particular, certificate store operations can be costly, so try to load all of your certificates at once and keep them in memory as long as is practical. That said, certificate chain validation always hits the certificate store first, so that is unavoidable without a custom X509CertificateChain implementation.

### LINQ
While we encourage the use of properly formatted LINQ for readability, some LINQ functions do not perform as quickly as we might like.
* Use concrete collection types where possible instead of interfaces. Many LINQ functions will do multiple type conversions when given an IEnumerable or other interface type.
* Use "Count > 0" instead of "Any()". When "Count" is available as a property instead of a method, that means the number is aleady stored in the object and does not need to be calculated.

### Static methods
Use static methods instead of instance methods where possible. Instance methods carry the entire object instance with them in a "this" pointer, which takes up more memory.

### Avoid dependency injection
Dependency injection, when it touches the product code, adds substantion memory and computational overhead and should be avoided. There should be no evidence of test code in the product code beyond the occasional constructor stub or interface, and remember that calling interfaces adds a type conversion step, so should be used sparingly.

## Functional considerations
### Streams
One of the main uses for COSE signing is to sign Software Bills of Materials (SBOM), which can sometimes exceed 2gb in size. When this happens, the file cannot fit into a byte array or memory stream because the count of bytes exceeds the maximum integer size. Instead, these need to be passed as Streams, or more specifically FileStreams. Note that only the payload file can exceed 2gb because the CoseSign1Message object has a backing byte array, and therefore when signing streams it only supports detached signing, whereas it can sign either detached or embedded when given a byte array, and embed-signed files can never exceed 2gb.

## Unit tests
All new or changed functionality must have unit tests (or integration tests if unit testing is not feasible) to verify that it works as expected.

### Testing frameworks
The test in this solution use the standard MSTest framework provided by Visual Studio, plus Fluent Assertions for syntax and Moq for mocking. While there are many great test frameworks out there, we ask that contributors limit themselves to these to prevent package bloat and reduce cognitive load for other contributors.

### Use of Moq ###
While Moq is a very popular and powerful tool, we believe in a "lean and clean" approach for better performance, readability, and debugging.
* Use Moq _only_ in test projects. Pull requests that add Moq or dependency injection to non-test projects will be blocked.
* Use Moq _only_ for necessity, not convenience. Mocking is appropriate for calls to resources that might not be available, such as a network or an outside program, or to avoid making changes to the host machine state, such as writing to the certificate store or registry. Otherwise, write files to temporary folders, use the TestCertificateUtils class to create temporary certificates, and test the real thing wherever possible.

### Use FluentAssertions syntax
For consistency, please use [FluentAssertions syntax](https://fluentassertions.com/introduction) for asserts.

## API design
The CoseHandler project features a user-centric API, designed to make COSE signing and validation as easy as possible. The user doesn't have to know anything beyond "I need to sign X file with Y certificate" or "I need to validate this signature against this payload." It doesn't matter if their certificate is a .pfx file or a thumbprint, or if the content they want to sign is a file, stream, or byte array, it just works. And if it doesn't work, it will tell them why in a way that is easy for a lay person to understand and correct, such as "The signing certificate must include a private key."
The underlying CoseSign1._x_ projects are intended for more advanced users and can flex more to fit the needs of the functionality.

## Do not break the existing API
If you want to enable a scenario that is not covered by the existing CoseHandler methods and overloads, the preferred practice is to add new ones. If your work invalidates any of the existing overloads, the missing parameters should be added as optional paramters with viable default values at the end of the call chain so as to not break existing applications.
If for any reason you have to break an existing public API, please flag the change so it gets a thorough review and so that breaking change notifications can go out before the change is published.

### Follow existing patterns
New methods and overloads added to CoseHandler should resemble the existing ones. Keep input parameters in the same order where possible, make sure you support file, stream, and byte array inputs where apporpriate, and support options for specifying certificates by object/file or thumbprint for signing operations.

## Coding style
### Full comment blocks for all public types and members
Each non-private type or member in a non-test project should have a full triple-slash comment block including a summary, and descriptions for all parameters, return value, and all possible exceptions, including those thrown by other members the current member calls into.
* Comment text should be in complete sentences, with a space after the slashes, the first letter capitalized, and a period at the end.
* Use correct comment tagging: 'see cref=' for other types, 'paramref name=' for other parameters.
* Optional parameters should start with "Optional. " and end with the default value if not null.
* Private members in non-test classes should have a one-line double-slash comment.

### Internal comments
The code should be easy enough for an intern to understand. Consider adding a comment before...
* ...any significant operation.
* ...any conditional block, loop structure, RegEx, or LINQ query.
* ...any line that contains a ternary or null-coalescing operator.
* ...any code that has to do something unintuitive.

### Line breaks
* Parameters in a method declaration should be wrapped and indented if:
    * There are more than three parameters, or
    * The line is > 120 characters long, including indentation, or
    * Any of the parameters include method calls or expressions.
* When calling one overload from within the expression body of another overload, you may group multiple paramater values on a single line as long as each value that is an expression or method call goes on its own line and the total line length is < 120 characters.
* Parameter values in method calls should be labeled unless the paramater name is obvious from the value being passed in.
* LINQ queries with more than three elements should wrap and indent at each element.
    * Simple sub-queries may remain on a single line, or may wrap and indent one tab deeper than their parent clause.
* Expressions and method calls that exceed 120 characters including indent, or otherwise look complex, should break at conceptual boundaries.
    * Ternary expressions should break after the "=" sign and retain the colon at the end of the line, so each line reads as a statement.
        * If you have to break a ternary expression at a question mark, indent the next line to show it's dependence on the question clause.
    * Other expressions should usually break just before a period or other connecting operator.
        * Always indent sub-expressions relative to their parent, and then go back a layer when you exit the sub-expression.

### Strings
Use interpolated strings with the $"Text {variable} more text" format. This is both more performant and easier to read than string.format, stringbuilders, or concatenation. Using "text " + "more text" to break lines during string initialization is fine.
* If you cannot create the whole string all at once, try to modify it as few times as possible.
* For multiline strings, use the @"" or $@"" [verbatim string literal syntax](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/tokens/verbatim) instead of "\r\n".

### Page structure
* Use file-scoped namespaces.
* Put all using statements in the global usings file except for static usings/aliases, which go after the namespace.
* Use the standard page order for member definitions: Constants, fields (private then public unless conceptually linked), properties, constructors, public methods (with pass-through overloads first), protected and internal methods, private methods.

