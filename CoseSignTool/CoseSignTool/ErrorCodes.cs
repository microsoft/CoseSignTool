// ---------------------------------------------------------------------------
// <copyright file="ErrorCodes.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ---------------------------------------------------------------------------

namespace CborExperiment
{

    /// <summary>
    /// Error codes used by ES.Build.COSESignTool
    /// </summary>
    public enum ErrorCodes
    {
        ErrorCode_NoSignedFile = 200,
        ErrorCode_PayloadNotFound = 201,
        ErrorCode_SignError = 202
    }
}