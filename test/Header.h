struct FuncInfoHeader
{
    union
    {
        struct
        {
            uint8_t isCatch : 1;  // 1 if this represents a catch funclet, 0 otherwise
            uint8_t isSeparated : 1;  // 1 if this function has separated code segments, 0 otherwise
            uint8_t BBT : 1;  // Flags set by Basic Block Transformations
            uint8_t UnwindMap : 1;  // Existence of Unwind Map RVA
            uint8_t TryBlockMap : 1;  // Existence of Try Block Map RVA
            uint8_t EHs : 1;  // EHs flag set
            uint8_t NoExcept : 1;  // NoExcept flag set
            uint8_t reserved : 1;
        };
        uint8_t value;
    };
};
struct FuncInfo4
{
    FuncInfoHeader      header;
    uint32_t            bbtFlags;            // flags that may be set by BBT processing

    int32_t             dispUnwindMap;       // Image relative offset of the unwind map
    int32_t             dispTryBlockMap;     // Image relative offset of the handler map
    int32_t             dispIPtoStateMap;    // Image relative offset of the IP to state map
    uint32_t            dispFrame;           // displacement of address of function frame wrt establisher frame, only used for catch funclets

};
struct EHRegistrationNode {
    /* void *			stackPtr */		// Stack ptr at entry to try (below address point)
    EHRegistrationNode* pNext;			// Next node in the chain
    void* frameHandler;	// The handler function for this frame
    int			state;			// The current state of this function
};
