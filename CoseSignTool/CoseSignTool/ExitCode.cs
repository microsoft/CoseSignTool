// ----------------------------------------------------------------------------------------
// <copyright file="ExitCodes.cs" company="Microsoft">
//      Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ----------------------------------------------------------------------------------------

namespace CoseSignTool
{
    // TODO: Make sure I've identified and flagged the different failure cases
    // Validation: 
    public enum ExitCode
    {
        Success = 0,
        HelpRequested = 9999,
        UnknownArgument = 1000,
        MissingRequiredOption = 1007,
        MissingArgumentValue = 1006,
        InvalidArgumentValue = 1004,
        FileNotFound = 1009,
        CertificateLoadFailure = 1888
    }
}
