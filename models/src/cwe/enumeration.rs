use serde::Deserialize;
use strum::{AsRefStr, EnumString};

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum Abstraction {
    Pillar,
    Class,
    Base,
    Variant,
    Compound,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum ArchitectureClass {
    Embedded,
    Microcomputer,
    Workstation,
    #[serde(rename = "Not Architecture-Specific")]
    #[strum(serialize = "Not Architecture-Specific")]
    NotArchitectureSpecific,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum ArchitectureName {
    Alpha,
    ARM,
    Itanium,
    #[serde(rename = "Power Architecture")]
    #[strum(serialize = "Power Architecture")]
    PowerArchitecture,
    SPARC,
    #[serde(rename = "x86")]
    #[strum(serialize = "x86")]
    X86,
    Other,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum DetectionEffectiveness {
    High,
    Moderate,
    #[serde(rename = "SOAR Partial")]
    #[strum(serialize = "SOAR Partial")]
    SoarPartial,
    Opportunistic,
    Limited,
    None,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum DetectionMethod {
    #[serde(rename = "Automated Analysis")]
    #[strum(serialize = "Automated Analysis")]
    AutomatedAnalysis,
    #[serde(rename = "Automated Dynamic Analysis")]
    #[strum(serialize = "Automated Dynamic Analysis")]
    AutomatedDynamicAnalysis,
    #[serde(rename = "Automated Static Analysis")]
    #[strum(serialize = "Automated Static Analysis")]
    AutomatedStaticAnalysis,
    #[serde(rename = "Automated Static Analysis - Source Code")]
    #[strum(serialize = "Automated Static Analysis - Source Code")]
    AutomatedStaticAnalysisSourceCode,
    #[serde(rename = "Automated Static Analysis - Binary or Bytecode")]
    #[strum(serialize = "Automated Static Analysis - Binary or Bytecode")]
    AutomatedStaticAnalysisBinaryOrBytecode,
    Fuzzing,
    #[serde(rename = "Manual Analysis")]
    #[strum(serialize = "Manual Analysis")]
    ManualAnalysis,
    #[serde(rename = "Manual Dynamic Analysis")]
    #[strum(serialize = "Manual Dynamic Analysis")]
    ManualDynamicAnalysis,
    #[serde(rename = "Manual Static Analysis")]
    #[strum(serialize = "Manual Static Analysis")]
    ManualStaticAnalysis,
    #[serde(rename = "Manual Static Analysis - Source Code")]
    #[strum(serialize = "Manual Static Analysis - Source Code")]
    ManualStaticAnalysisSourceCode,
    #[serde(rename = "Manual Static Analysis - Binary or Bytecode")]
    #[strum(serialize = "Manual Static Analysis - Binary or Bytecode")]
    ManualStaticAnalysisBinaryOrBytecode,
    #[serde(rename = "White Box")]
    #[strum(serialize = "White Box")]
    WhiteBox,
    #[serde(rename = "Black Box")]
    #[strum(serialize = "Black Box")]
    BlackBox,
    #[serde(rename = "Architecture or Design Review")]
    #[strum(serialize = "Architecture or Design Review")]
    ArchitectureOrDesignReview,
    #[serde(rename = "Dynamic Analysis with Manual Results Interpretation")]
    #[strum(serialize = "Dynamic Analysis with Manual Results Interpretation")]
    DynamicAnalysisWithManualResultsInterpretation,
    #[serde(rename = "Dynamic Analysis with Automated Results Interpretation")]
    #[strum(serialize = "Dynamic Analysis with Automated Results Interpretation")]
    DynamicAnalysisWithAutomatedResultsInterpretation,
    #[serde(rename = "Formal Verification")]
    #[strum(serialize = "Formal Verification")]
    FormalVerification,
    #[serde(rename = "Simulation / Emulation")]
    #[strum(serialize = "Simulation / Emulation")]
    SimulationEmulation,
    Other,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum Effectiveness {
    High,
    Moderate,
    Limited,
    Incidental,
    #[serde(rename = "Discouraged Common Practice")]
    #[strum(serialize = "Discouraged Common Practice")]
    DiscouragedCommonPractice,
    #[serde(rename = "Defense in Depth")]
    #[strum(serialize = "Defense in Depth")]
    DefenseInDepth,
    None,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum FunctionalArea {
    Authentication,
    Authorization,
    #[serde(rename = "Code Libraries")]
    #[strum(serialize = "Code Libraries")]
    CodeLibraries,
    Counters,
    Cryptography,
    #[serde(rename = "Error Handling")]
    #[strum(serialize = "Error Handling")]
    ErrorHandling,
    #[serde(rename = "Interprocess Communication")]
    #[strum(serialize = "Interprocess Communication")]
    InterprocessCommunication,
    #[serde(rename = "File Processing")]
    #[strum(serialize = "File Processing")]
    FileProcessing,
    Logging,
    #[serde(rename = "Memory Management")]
    #[strum(serialize = "Memory Management")]
    MemoryManagement,
    Networking,
    #[serde(rename = "Number Processing")]
    #[strum(serialize = "Number Processing")]
    NumberProcessing,
    #[serde(rename = "Program Invocation")]
    #[strum(serialize = "Program Invocation")]
    ProgramInvocation,
    #[serde(rename = "Protection Mechanism")]
    #[strum(serialize = "Protection Mechanism")]
    ProtectionMechanism,
    #[serde(rename = "Session Management")]
    #[strum(serialize = "Session Management")]
    SessionManagement,
    Signals,
    #[serde(rename = "String Processing")]
    #[strum(serialize = "String Processing")]
    StringProcessing,
    #[serde(rename = "Not Functional-Area-Specific")]
    #[strum(serialize = "Not Functional-Area-Specific")]
    NotFunctionalAreaSpecific,
    Power,
    Clock,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum Importance {
    Normal,
    Critical,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum LanguageClass {
    Assembly,
    Compiled,
    #[serde(rename = "Hardware Description Language")]
    #[strum(serialize = "Hardware Description Language")]
    HardwareDescriptionLanguage,
    Interpreted,
    #[serde(rename = "Object-Oriented")]
    #[strum(serialize = "Object-Oriented")]
    ObjectOriented,
    #[serde(rename = "Memory-Unsafe")]
    #[strum(serialize = "Memory-Unsafe")]
    MemoryUnsafe,
    #[serde(rename = "Not Language-Specific")]
    #[strum(serialize = "Not Language-Specific")]
    NotLanguageSpecific,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum LanguageName {
    Ada,
    #[serde(rename = "ARM Assembly")]
    #[strum(serialize = "ARM Assembly")]
    ArmAssembly,
    ASP,
    #[serde(rename = "ASP.NET")]
    #[strum(serialize = "ASP.NET")]
    AspNet,
    Basic,
    C,
    #[serde(rename = "C++")]
    #[strum(serialize = "C++")]
    Cpp,
    #[serde(rename = "C#")]
    #[strum(serialize = "C#")]
    CSharp,
    COBOL,
    Fortran,
    #[serde(rename = "F#")]
    #[strum(serialize = "F#")]
    FSharp,
    Go,
    HTML,
    Java,
    JavaScript,
    JSON,
    JSP,
    #[serde(rename = "Objective-C")]
    #[strum(serialize = "Objective-C")]
    ObjectiveC,
    Pascal,
    Perl,
    PHP,
    Pseudocode,
    Python,
    Ruby,
    Rust,
    Shell,
    SQL,
    Swift,
    #[serde(rename = "VB.NET")]
    #[strum(serialize = "VB.NET")]
    VbNet,
    Verilog,
    VHDL,
    XML,
    #[serde(rename = "x86 Assembly")]
    #[strum(serialize = "x86 Assembly")]
    X86Assembly,
    Other,
    #[serde(rename = "Algorithm")]
    #[strum(serialize = "Algorithm")]
    Algorithm,
    #[serde(rename = "SystemVerilog")]
    #[strum(serialize = "SystemVerilog")]
    SystemVerilog,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum Likelihood {
    High,
    Medium,
    Low,
    Unknown,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum MitigationStrategy {
    #[serde(rename = "Attack Surface Reduction")]
    #[strum(serialize = "Attack Surface Reduction")]
    AttackSurfaceReduction,
    #[serde(rename = "Compilation or Build Hardening")]
    #[strum(serialize = "Compilation or Build Hardening")]
    CompilationOrBuildHardening,
    #[serde(rename = "Enforcement by Conversion")]
    #[strum(serialize = "Enforcement by Conversion")]
    EnforcementByConversion,
    #[serde(rename = "Environment Hardening")]
    #[strum(serialize = "Environment Hardening")]
    EnvironmentHardening,
    Firewall,
    #[serde(rename = "Input Validation")]
    #[strum(serialize = "Input Validation")]
    InputValidation,
    #[serde(rename = "Language Selection")]
    #[strum(serialize = "Language Selection")]
    LanguageSelection,
    #[serde(rename = "Libraries or Frameworks")]
    #[strum(serialize = "Libraries or Frameworks")]
    LibrariesOrFrameworks,
    #[serde(rename = "Resource Limitation")]
    #[strum(serialize = "Resource Limitation")]
    ResourceLimitation,
    #[serde(rename = "Output Encoding")]
    #[strum(serialize = "Output Encoding")]
    OutputEncoding,
    Parameterization,
    Refactoring,
    #[serde(rename = "Sandbox or Jail")]
    #[strum(serialize = "Sandbox or Jail")]
    SandboxOrJail,
    #[serde(rename = "Separation of Privilege")]
    #[strum(serialize = "Separation of Privilege")]
    SeparationOfPrivilege,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum NoteType {
    #[serde(rename = "Applicable Platform")]
    #[strum(serialize = "Applicable Platform")]
    ApplicablePlatform,
    Maintenance,
    Relationship,
    #[serde(rename = "Research Gap")]
    #[strum(serialize = "Research Gap")]
    ResearchGap,
    Terminology,
    Theoretical,
    Other,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum Ordinal {
    Primary,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum Ordinality {
    Indirect,
    Primary,
    Resultant,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum OperatingSystemClass {
    Linux,
    #[serde(rename = "macOS")]
    #[strum(serialize = "macOS")]
    MacOs,
    Unix,
    Windows,
    #[serde(rename = "Not OS-Specific")]
    #[strum(serialize = "Not OS-Specific")]
    NotOsSpecific,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum OperatingSystemName {
    AIX,
    Android,
    #[serde(rename = "BlackBerry OS")]
    #[strum(serialize = "BlackBerry OS")]
    BlackBerryOs,
    #[serde(rename = "Chrome OS")]
    #[strum(serialize = "Chrome OS")]
    ChromeOs,
    Darwin,
    FreeBSD,
    #[serde(rename = "iOS")]
    #[strum(serialize = "iOS")]
    IOs,
    #[serde(rename = "macOS")]
    #[strum(serialize = "macOS")]
    MacOs,
    NetBSD,
    OpenBSD,
    #[serde(rename = "Red Hat")]
    #[strum(serialize = "Red Hat")]
    RedHat,
    Solaris,
    SUSE,
    #[serde(rename = "tvOS")]
    #[strum(serialize = "tvOS")]
    TvOs,
    Ubuntu,
    #[serde(rename = "watchOS")]
    #[strum(serialize = "watchOS")]
    WatchOs,
    #[serde(rename = "Windows 9x")]
    #[strum(serialize = "Windows 9x")]
    Windows9x,
    #[serde(rename = "Windows Embedded")]
    #[strum(serialize = "Windows Embedded")]
    WindowsEmbedded,
    #[serde(rename = "Windows NT")]
    #[strum(serialize = "Windows NT")]
    WindowsNt,
    #[serde(rename = "Other")]
    #[strum(serialize = "Other")]
    Other,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum Phase {
    Policy,
    Requirements,
    #[serde(rename = "Architecture and Design")]
    #[strum(serialize = "Architecture and Design")]
    ArchitectureAndDesign,
    Implementation,
    #[serde(rename = "Build and Compilation")]
    #[strum(serialize = "Build and Compilation")]
    BuildAndCompilation,
    Testing,
    Documentation,
    Bundling,
    Distribution,
    Installation,
    #[serde(rename = "System Configuration")]
    #[strum(serialize = "System Configuration")]
    SystemConfiguration,
    Operation,
    #[serde(rename = "Patching and Maintenance")]
    #[strum(serialize = "Patching and Maintenance")]
    PatchingAndMaintenance,
    Porting,
    Integration,
    Manufacturing,
    #[serde(rename = "Decommissioning and End-of-Life")]
    #[strum(serialize = "Decommissioning and End-of-Life")]
    DecommissioningAndEndOfLife,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum Prevalence {
    Often,
    Sometimes,
    Rarely,
    Undetermined,
    #[serde(rename = "None")]
    #[strum(serialize = "None")]
    None,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum Reason {
    Abstraction,
    Category,
    View,
    Deprecated,
    #[serde(rename = "Potential Deprecation")]
    #[strum(serialize = "Potential Deprecation")]
    PotentialDeprecation,
    #[serde(rename = "Frequent Misuse")]
    #[strum(serialize = "Frequent Misuse")]
    FrequentMisuse,
    #[serde(rename = "Frequent Misinterpretation")]
    #[strum(serialize = "Frequent Misinterpretation")]
    FrequentMisinterpretation,
    #[serde(rename = "Multiple Use")]
    #[strum(serialize = "Multiple Use")]
    MultipleUse,
    #[serde(rename = "CWE Overlap")]
    #[strum(serialize = "CWE Overlap")]
    CweOverlap,
    #[serde(rename = "Acceptable-Use")]
    #[strum(serialize = "Acceptable-Use")]
    AcceptableUse,
    #[serde(rename = "Potential Major Changes")]
    #[strum(serialize = "Potential Major Changes")]
    PotentialMajorChanges,
    Other,
    #[serde(rename = "Grouping")]
    #[strum(serialize = "Grouping")]
    Grouping,
    #[serde(rename = "Frequently-Resultant")]
    #[strum(serialize = "Frequently-Resultant")]
    FrequentlyResultant,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum RelatedNature {
    ChildOf,
    ParentOf,
    StartsWith,
    CanFollow,
    CanPrecede,
    RequiredBy,
    Requires,
    CanAlsoBe,
    PeerOf,
    #[serde(rename = "Overlaps")]
    #[strum(serialize = "Overlaps")]
    Overlaps,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum Resource {
    CPU,
    #[serde(rename = "File or Directory")]
    #[strum(serialize = "File or Directory")]
    FileOrDirectory,
    Memory,
    #[serde(rename = "System Process")]
    #[strum(serialize = "System Process")]
    SystemProcess,
    Other,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum Scope {
    Confidentiality,
    Integrity,
    Availability,
    #[serde(rename = "Access Control")]
    #[strum(serialize = "Access Control")]
    AccessControl,
    Accountability,
    Authentication,
    Authorization,
    #[serde(rename = "Non-Repudiation")]
    #[strum(serialize = "Non-Repudiation")]
    NonRepudiation,
    Other,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum Status {
    Deprecated,
    Draft,
    Incomplete,
    Obsolete,
    Stable,
    Usable,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum Stakeholder {
    #[serde(rename = "Academic Researchers")]
    #[strum(serialize = "Academic Researchers")]
    AcademicResearchers,
    #[serde(rename = "Applied Researchers")]
    #[strum(serialize = "Applied Researchers")]
    AppliedResearchers,
    #[serde(rename = "Assessment Teams")]
    #[strum(serialize = "Assessment Teams")]
    AssessmentTeams,
    #[serde(rename = "Assessment Tool Vendors")]
    #[strum(serialize = "Assessment Tool Vendors")]
    AssessmentToolVendors,
    #[serde(rename = "CWE Team")]
    #[strum(serialize = "CWE Team")]
    CweTeam,
    Educators,
    #[serde(rename = "Hardware Designers")]
    #[strum(serialize = "Hardware Designers")]
    HardwareDesigners,
    #[serde(rename = "Information Providers")]
    #[strum(serialize = "Information Providers")]
    InformationProviders,
    #[serde(rename = "Product Customers")]
    #[strum(serialize = "Product Customers")]
    ProductCustomers,
    #[serde(rename = "Product Vendors")]
    #[strum(serialize = "Product Vendors")]
    ProductVendors,
    #[serde(rename = "Software Developers")]
    #[strum(serialize = "Software Developers")]
    SoftwareDevelopers,
    #[serde(rename = "Vulnerability Analysts")]
    #[strum(serialize = "Vulnerability Analysts")]
    VulnerabilityAnalysts,
    Other,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum Structure {
    Chain,
    Composite,
    Simple,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum StructuredCodeNature {
    Attack,
    Bad,
    Good,
    Informative,
    Mitigation,
    Result,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum TaxonomyMappingFit {
    Exact,
    #[serde(rename = "CWE More Abstract")]
    #[strum(serialize = "CWE More Abstract")]
    CweMoreAbstract,
    #[serde(rename = "CWE More Specific")]
    #[strum(serialize = "CWE More Specific")]
    CweMoreSpecific,
    Imprecise,
    Perspective,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum TaxonomyName {
    #[serde(rename = "7 Pernicious Kingdoms")]
    #[strum(serialize = "7 Pernicious Kingdoms")]
    SevenPerniciousKingdoms,
    #[serde(rename = "19 Deadly Sins")]
    #[strum(serialize = "19 Deadly Sins")]
    NineteenDeadlySins,
    Aslam,
    Bishop,
    #[serde(rename = "CERT C Secure Coding")]
    #[strum(serialize = "CERT C Secure Coding")]
    CertCSecureCoding,
    #[serde(rename = "CERT C++ Secure Coding")]
    #[strum(serialize = "CERT C++ Secure Coding")]
    CertCppSecureCoding,
    #[serde(rename = "The CERT Oracle Secure Coding Standard for Java (2011)")]
    #[strum(serialize = "The CERT Oracle Secure Coding Standard for Java (2011)")]
    CertOracleSecureCodingStandardForJava2011,
    CLASP,
    #[serde(rename = "ISA/IEC 62443")]
    #[strum(serialize = "ISA/IEC 62443")]
    IsaIec62443,
    Landwehr,
    #[serde(rename = "OMG ASCSM")]
    #[strum(serialize = "OMG ASCSM")]
    OmgAscsm,
    #[serde(rename = "OMG ASCRM")]
    #[strum(serialize = "OMG ASCRM")]
    OmgAscrm,
    #[serde(rename = "OMG ASCMM")]
    #[strum(serialize = "OMG ASCMM")]
    OmgAscmm,
    #[serde(rename = "OMG ASCPEM")]
    #[strum(serialize = "OMG ASCPEM")]
    OmgAscpem,
    #[serde(rename = "OWASP Top Ten 2004")]
    #[strum(serialize = "OWASP Top Ten 2004")]
    OwaspTopTen2004,
    #[serde(rename = "OWASP Top Ten 2007")]
    #[strum(serialize = "OWASP Top Ten 2007")]
    OwaspTopTen2007,
    #[serde(rename = "OWASP Top Ten")]
    #[strum(serialize = "OWASP Top Ten")]
    OwaspTopTen,
    PLOVER,
    #[serde(rename = "Protection Analysis")]
    #[strum(serialize = "Protection Analysis")]
    ProtectionAnalysis,
    RISOS,
    #[serde(rename = "SEI CERT C Coding Standard")]
    #[strum(serialize = "SEI CERT C Coding Standard")]
    SeiCertCCodingStandard,
    #[serde(rename = "SEI CERT C++ Coding Standard")]
    #[strum(serialize = "SEI CERT C++ Coding Standard")]
    SeiCertCppCodingStandard,
    #[serde(rename = "SEI CERT Oracle Coding Standard for Java")]
    #[strum(serialize = "SEI CERT Oracle Coding Standard for Java")]
    SeiCertOracleCodingStandardForJava,
    #[serde(rename = "SEI CERT Perl Coding Standard")]
    #[strum(serialize = "SEI CERT Perl Coding Standard")]
    SeiCertPerlCodingStandard,
    #[serde(rename = "Software Fault Patterns")]
    #[strum(serialize = "Software Fault Patterns")]
    SoftwareFaultPatterns,
    #[serde(rename = "Weber, Karger, Paradkar")]
    #[strum(serialize = "Weber, Karger, Paradkar")]
    WeberKargerParadkar,
    WASC,
    #[serde(rename = "OpenSSF Secure Coding Guide for Python")]
    #[strum(serialize = "OpenSSF Secure Coding Guide for Python")]
    OpenSSFSecureCodingGuideForPython,
    #[serde(rename = "OWASP Golang Secure Coding Practices Guide")]
    #[strum(serialize = "OWASP Golang Secure Coding Practices Guide")]
    OWASPGolangSecureCodingPracticesGuide,
    #[serde(rename = "PLC Top 20")]
    #[strum(serialize = "PLC Top 20")]
    PLCTop20,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum TechnicalImpact {
    #[serde(rename = "Modify Memory")]
    #[strum(serialize = "Modify Memory")]
    ModifyMemory,
    #[serde(rename = "Read Memory")]
    #[strum(serialize = "Read Memory")]
    ReadMemory,
    #[serde(rename = "Modify Files or Directories")]
    #[strum(serialize = "Modify Files or Directories")]
    ModifyFilesOrDirectories,
    #[serde(rename = "Read Files or Directories")]
    #[strum(serialize = "Read Files or Directories")]
    ReadFilesOrDirectories,
    #[serde(rename = "Modify Application Data")]
    #[strum(serialize = "Modify Application Data")]
    ModifyApplicationData,
    #[serde(rename = "Read Application Data")]
    #[strum(serialize = "Read Application Data")]
    ReadApplicationData,
    #[serde(rename = "DoS: Crash, Exit, or Restart")]
    #[strum(serialize = "DoS: Crash, Exit, or Restart")]
    DosCrashExitOrRestart,
    #[serde(rename = "DoS: Amplification")]
    #[strum(serialize = "DoS: Amplification")]
    DosAmplification,
    #[serde(rename = "DoS: Instability")]
    #[strum(serialize = "DoS: Instability")]
    DosInstability,
    #[serde(rename = "DoS: Resource Consumption (CPU)")]
    #[strum(serialize = "DoS: Resource Consumption (CPU)")]
    DosResourceConsumptionCpu,
    #[serde(rename = "DoS: Resource Consumption (Memory)")]
    #[strum(serialize = "DoS: Resource Consumption (Memory)")]
    DosResourceConsumptionMemory,
    #[serde(rename = "DoS: Resource Consumption (Other)")]
    #[strum(serialize = "DoS: Resource Consumption (Other)")]
    DosResourceConsumptionOther,
    #[serde(rename = "Execute Unauthorized Code or Commands")]
    #[strum(serialize = "Execute Unauthorized Code or Commands")]
    ExecuteUnauthorizedCodeOrCommands,
    #[serde(rename = "Gain Privileges or Assume Identity")]
    #[strum(serialize = "Gain Privileges or Assume Identity")]
    GainPrivilegesOrAssumeIdentity,
    #[serde(rename = "Bypass Protection Mechanism")]
    #[strum(serialize = "Bypass Protection Mechanism")]
    BypassProtectionMechanism,
    #[serde(rename = "Hide Activities")]
    #[strum(serialize = "Hide Activities")]
    HideActivities,
    #[serde(rename = "Alter Execution Logic")]
    #[strum(serialize = "Alter Execution Logic")]
    AlterExecutionLogic,
    #[serde(rename = "Quality Degradation")]
    #[strum(serialize = "Quality Degradation")]
    QualityDegradation,
    #[serde(rename = "Unexpected State")]
    #[strum(serialize = "Unexpected State")]
    UnexpectedState,
    #[serde(rename = "Varies by Context")]
    #[strum(serialize = "Varies by Context")]
    VariesByContext,
    #[serde(rename = "Increase Analytical Complexity")]
    #[strum(serialize = "Increase Analytical Complexity")]
    IncreaseAnalyticalComplexity,
    #[serde(rename = "Reduce Maintainability")]
    #[strum(serialize = "Reduce Maintainability")]
    ReduceMaintainability,
    #[serde(rename = "Reduce Performance")]
    #[strum(serialize = "Reduce Performance")]
    ReducePerformance,
    #[serde(rename = "Reduce Reliability")]
    #[strum(serialize = "Reduce Reliability")]
    ReduceReliability,
    Other,
    #[serde(rename = "DoS: Prevent Access")]
    #[strum(serialize = "DoS: Prevent Access")]
    DoSPreventAccess,
    #[serde(rename = "DoS: Other")]
    #[strum(serialize = "DoS: Other")]
    DoSOther,
    #[serde(rename = "Undefined Behavior")]
    #[strum(serialize = "Undefined Behavior")]
    UndefinedBehavior,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum TechnologyClass {
    #[serde(rename = "Client Server")]
    #[strum(serialize = "Client Server")]
    ClientServer,
    #[serde(rename = "Cloud Computing")]
    #[strum(serialize = "Cloud Computing")]
    CloudComputing,
    #[serde(rename = "ICS/OT")]
    #[strum(serialize = "ICS/OT")]
    IcsOt,
    Mainframe,
    Mobile,
    #[serde(rename = "N-Tier")]
    #[strum(serialize = "N-Tier")]
    NTier,
    SOA,
    #[serde(rename = "System on Chip")]
    #[strum(serialize = "System on Chip")]
    SystemOnChip,
    #[serde(rename = "Web Based")]
    #[strum(serialize = "Web Based")]
    WebBased,
    #[serde(rename = "Not Technology-Specific")]
    #[strum(serialize = "Not Technology-Specific")]
    NotTechnologySpecific,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum TechnologyName {
    #[serde(rename = "AI/ML")]
    #[strum(serialize = "AI/ML")]
    AiMl,
    #[serde(rename = "Web Server")]
    #[strum(serialize = "Web Server")]
    WebServer,
    #[serde(rename = "Database Server")]
    #[strum(serialize = "Database Server")]
    DatabaseServer,
    #[serde(rename = "Accelerator Hardware")]
    #[strum(serialize = "Accelerator Hardware")]
    AcceleratorHardware,
    #[serde(rename = "Analog and Mixed Signal Hardware")]
    #[strum(serialize = "Analog and Mixed Signal Hardware")]
    AnalogAndMixedSignalHardware,
    #[serde(rename = "Audio/Video Hardware")]
    #[strum(serialize = "Audio/Video Hardware")]
    AudioVideoHardware,
    #[serde(rename = "Bus/Interface Hardware")]
    #[strum(serialize = "Bus/Interface Hardware")]
    BusInterfaceHardware,
    #[serde(rename = "Clock/Counter Hardware")]
    #[strum(serialize = "Clock/Counter Hardware")]
    ClockCounterHardware,
    #[serde(rename = "Communication Hardware")]
    #[strum(serialize = "Communication Hardware")]
    CommunicationHardware,
    #[serde(rename = "Controller Hardware")]
    #[strum(serialize = "Controller Hardware")]
    ControllerHardware,
    #[serde(rename = "Memory Hardware")]
    #[strum(serialize = "Memory Hardware")]
    MemoryHardware,
    #[serde(rename = "Microcontroller Hardware")]
    #[strum(serialize = "Microcontroller Hardware")]
    MicrocontrollerHardware,
    #[serde(rename = "Network on Chip Hardware")]
    #[strum(serialize = "Network on Chip Hardware")]
    NetworkOnChipHardware,
    #[serde(rename = "Power Management Hardware")]
    #[strum(serialize = "Power Management Hardware")]
    PowerManagementHardware,
    #[serde(rename = "Processor Hardware")]
    #[strum(serialize = "Processor Hardware")]
    ProcessorHardware,
    #[serde(rename = "Security Hardware")]
    #[strum(serialize = "Security Hardware")]
    SecurityHardware,
    #[serde(rename = "Sensor Hardware")]
    #[strum(serialize = "Sensor Hardware")]
    SensorHardware,
    #[serde(rename = "Storage Hardware")]
    #[strum(serialize = "Storage Hardware")]
    StorageHardware,
    #[serde(rename = "Test/Debug Hardware")]
    #[strum(serialize = "Test/Debug Hardware")]
    TestDebugHardware,
    Other,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum Usage {
    Discouraged,
    Prohibited,
    Allowed,
    #[serde(rename = "Allowed-with-Review")]
    #[strum(serialize = "Allowed-with-Review")]
    AllowedWithReview,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum ViewType {
    Implicit,
    Explicit,
    Graph,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum CustomPhaseDomain {
    #[serde(rename = "AI")]
    #[strum(serialize = "AI")]
    AI,
    #[serde(rename = "Hardware")]
    #[strum(serialize = "Hardware")]
    Hardware,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum Dimension {
    #[serde(rename = "Behavior-Type")]
    #[strum(serialize = "Behavior-Type")]
    BehaviorType,
    #[serde(rename = "Behavior-Property")]
    #[strum(serialize = "Behavior-Property")]
    BehaviorProperty,
    #[serde(rename = "Resource-Type")]
    #[strum(serialize = "Resource-Type")]
    ResourceType,
    #[serde(rename = "Resource-Property")]
    #[strum(serialize = "Resource-Property")]
    ResourceProperty,
    #[serde(rename = "Input-Type")]
    #[strum(serialize = "Input-Type")]
    InputType,
    #[serde(rename = "Input-Property")]
    #[strum(serialize = "Input-Property")]
    InputProperty,
    #[serde(rename = "Info-Type")]
    #[strum(serialize = "Info-Type")]
    InfoType,
    #[serde(rename = "Info-Property")]
    #[strum(serialize = "Info-Property")]
    InfoProperty,
    #[serde(rename = "Code-Type")]
    #[strum(serialize = "Code-Type")]
    CodeType,
    #[serde(rename = "Code-Property")]
    #[strum(serialize = "Code-Property")]
    CodeProperty,
    #[serde(rename = "Technology")]
    #[strum(serialize = "Technology")]
    Technology,
    #[serde(rename = "Language-Type")]
    #[strum(serialize = "Language-Type")]
    LanguageType,
    #[serde(rename = "Language-Property")]
    #[strum(serialize = "Language-Property")]
    LanguageProperty,
    #[serde(rename = "Framework")]
    #[strum(serialize = "Framework")]
    Framework,
    #[serde(rename = "Common-Name")]
    #[strum(serialize = "Common-Name")]
    CommonName,
    #[serde(rename = "Attack")]
    #[strum(serialize = "Attack")]
    Attack,
    #[serde(rename = "Acronym")]
    #[strum(serialize = "Acronym")]
    Acronym,
    #[serde(rename = "Other")]
    #[strum(serialize = "Other")]
    Other,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum AlternateTermRole {
    #[serde(rename = "Abbreviation")]
    #[strum(serialize = "Abbreviation")]
    Abbreviation,
    #[serde(rename = "Acronym")]
    #[strum(serialize = "Acronym")]
    Acronym,
    #[serde(rename = "Alternate-Spelling")]
    #[strum(serialize = "Alternate-Spelling")]
    AlternateSpelling,
    #[serde(rename = "Attack-Focused")]
    #[strum(serialize = "Attack-Focused")]
    AttackFocused,
    #[serde(rename = "Impact-Oriented")]
    #[strum(serialize = "Impact-Oriented")]
    ImpactOriented,
    #[serde(rename = "Multi-Weakness")]
    #[strum(serialize = "Multi-Weakness")]
    MultiWeakness,
    #[serde(rename = "Multiple-Interpretation")]
    #[strum(serialize = "Multiple-Interpretation")]
    MultipleInterpretation,
    #[serde(rename = "Common-Name")]
    #[strum(serialize = "Common-Name")]
    CommonName,
    #[serde(rename = "Discouraged")]
    #[strum(serialize = "Discouraged")]
    Discouraged,
    #[serde(rename = "Legacy")]
    #[strum(serialize = "Legacy")]
    Legacy,
    #[serde(rename = "Other")]
    #[strum(serialize = "Other")]
    Other,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum ObexRationale {
    #[serde(rename = "Chain")]
    #[strum(serialize = "Chain")]
    Chain,
    #[serde(rename = "Early-Publication")]
    #[strum(serialize = "Early-Publication")]
    EarlyPublication,
    #[serde(rename = "Influential/Newsworthy")]
    #[strum(serialize = "Influential/Newsworthy")]
    InfluentialNewsworthy,
    #[serde(rename = "Language-Variety")]
    #[strum(serialize = "Language-Variety")]
    LanguageVariety,
    #[serde(rename = "Product-Variety")]
    #[strum(serialize = "Product-Variety")]
    ProductVariety,
    #[serde(rename = "Attack-Surface")]
    #[strum(serialize = "Attack-Surface")]
    AttackSurface,
    #[serde(rename = "Other")]
    #[strum(serialize = "Other")]
    Other,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum AIPhase {
    #[serde(rename = "Data Collection")]
    #[strum(serialize = "Data Collection")]
    DataCollection,
    #[serde(rename = "Training")]
    #[strum(serialize = "Training")]
    Training,
    #[serde(rename = "Fine-tuning")]
    #[strum(serialize = "Fine-tuning")]
    FineTuning,
    #[serde(rename = "Testing")]
    #[strum(serialize = "Testing")]
    Testing,
    #[serde(rename = "Tokenization")]
    #[strum(serialize = "Tokenization")]
    Tokenization,
    #[serde(rename = "Prompting")]
    #[strum(serialize = "Prompting")]
    Prompting,
    #[serde(rename = "Output Processing")]
    #[strum(serialize = "Output Processing")]
    OutputProcessing,
    #[serde(rename = "Component Interaction")]
    #[strum(serialize = "Component Interaction")]
    ComponentInteraction,
    #[serde(rename = "Re-training / Feedback")]
    #[strum(serialize = "Re-training / Feedback")]
    ReTrainingFeedback,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum HardwarePhase {
    #[serde(rename = "Hardware Requirements")]
    #[strum(serialize = "Hardware Requirements")]
    HardwareRequirements,
    #[serde(rename = "Hardware Architecture")]
    #[strum(serialize = "Hardware Architecture")]
    HardwareArchitecture,
    #[serde(rename = "Hardware Microarchitecture")]
    #[strum(serialize = "Hardware Microarchitecture")]
    HardwareMicroarchitecture,
    #[serde(rename = "Implementation & Physical Design")]
    #[strum(serialize = "Implementation & Physical Design")]
    ImplementationPhysicalDesign,
    #[serde(rename = "Pre-Manufacturing Verification")]
    #[strum(serialize = "Pre-Manufacturing Verification")]
    PreManufacturingVerification,
    #[serde(rename = "Hardware Manufacturing")]
    #[strum(serialize = "Hardware Manufacturing")]
    HardwareManufacturing,
    #[serde(rename = "Post-Manufacturing Validation")]
    #[strum(serialize = "Post-Manufacturing Validation")]
    PostManufacturingValidation,
    #[serde(rename = "Device Configuration & Personalization")]
    #[strum(serialize = "Device Configuration & Personalization")]
    DeviceConfigurationPersonalization,
    #[serde(rename = "Device / System Integration")]
    #[strum(serialize = "Device / System Integration")]
    DeviceSystemIntegration,
    #[serde(rename = "Field Operations & Sustainment")]
    #[strum(serialize = "Field Operations & Sustainment")]
    FieldOperationsSustainment,
    #[serde(rename = "Reuse")]
    #[strum(serialize = "Reuse")]
    Reuse,
    #[serde(rename = "Decommissioning")]
    #[strum(serialize = "Decommissioning")]
    Decommissioning,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum ReferenceAccessRestrictions {
    #[serde(rename = "None")]
    #[strum(serialize = "None")]
    None,
    #[serde(rename = "Proprietary-Subscription")]
    #[strum(serialize = "Proprietary-Subscription")]
    ProprietarySubscription,
    #[serde(rename = "Minimal-Registration")]
    #[strum(serialize = "Minimal-Registration")]
    MinimalRegistration,
    #[serde(rename = "Removed")]
    #[strum(serialize = "Removed")]
    Removed,
    #[serde(rename = "Other")]
    #[strum(serialize = "Other")]
    Other,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum ReferenceMediaType {
    #[serde(rename = "Text")]
    #[strum(serialize = "Text")]
    Text,
    #[serde(rename = "Common-Proprietary-Text")]
    #[strum(serialize = "Common-Proprietary-Text")]
    CommonProprietaryText,
    #[serde(rename = "Video")]
    #[strum(serialize = "Video")]
    Video,
    #[serde(rename = "Audio")]
    #[strum(serialize = "Audio")]
    Audio,
    #[serde(rename = "Other")]
    #[strum(serialize = "Other")]
    Other,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum ReferenceRationale {
    #[serde(rename = "Example")]
    #[strum(serialize = "Example")]
    Example,
    #[serde(rename = "Early-Publication")]
    #[strum(serialize = "Early-Publication")]
    EarlyPublication,
    #[serde(rename = "Influential/Newsworthy")]
    #[strum(serialize = "Influential/Newsworthy")]
    InfluentialNewsworthy,
    #[serde(rename = "Manual/Man Pages")]
    #[strum(serialize = "Manual/Man Pages")]
    ManualManPages,
    #[serde(rename = "Mitigation-Based")]
    #[strum(serialize = "Mitigation-Based")]
    MitigationBased,
    #[serde(rename = "Secure-Development-Rules")]
    #[strum(serialize = "Secure-Development-Rules")]
    SecureDevelopmentRules,
    #[serde(rename = "Other")]
    #[strum(serialize = "Other")]
    Other,
}
