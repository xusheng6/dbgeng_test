#include <iostream>
#define NOMINMAX
#include <windows.h>
#include <dbgeng.h>
#include <thread>
#include <chrono>

#define QUERY_DEBUG_INTERFACE(query, out) \
	if (const auto result = m_debugClient->QueryInterface(__uuidof(query), reinterpret_cast<void**>(out)); \
		result != S_OK) \
	throw std::runtime_error("Failed to create " #query)

void DumpAllRegisters(IDebugRegisters* m_debugRegisters)
{
    unsigned long register_count {};
    if (m_debugRegisters->GetNumberRegisters(&register_count) != S_OK)
    {
        std::cout << "GetNumberRegisters() failed" << std::endl;
        return;
    }

    std::cout << "there are " << register_count << " registers" << std::endl;

    for (std::size_t reg_index {}; reg_index < register_count; reg_index++)
    {
        unsigned long reg_length {};
        DEBUG_REGISTER_DESCRIPTION reg_description {};

        char out[256];
        if (m_debugRegisters->GetDescription(reg_index, out, 256, &reg_length, &reg_description) != S_OK)
        {
            std::cout << "fail to get register with index " << reg_index << std::endl;
            continue;
        }
        std::cout << "register " << reg_index << ", name length: " << reg_length << ", name: " << out << std::endl;
    }
}

uint64_t ReadRegister(IDebugRegisters* m_debugRegisters, const std::string& reg)
{
    unsigned long reg_index{};
    DEBUG_VALUE debug_value{};

    if (m_debugRegisters->GetIndexByName(reg.c_str(), &reg_index) != S_OK)
        return 0;

    if (m_debugRegisters->GetValue(reg_index, &debug_value) != S_OK)
        return 0;

    return debug_value.I64;
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        std::cout << "Pas in pass if execution traccee" << std::endl;
        return -1;
    }

    if (!SetDllDirectoryA(R"(C:\Users\xushe\Downloads\Microsoft.WinDbg_1.2210.3001.0_x64__8wekyb3d8bbwe\amd64)"))
    {
        std::cout << "SetDllDirectoryA failed" << std::endl;
        return -1;
    }

    HMODULE handle;
    handle = LoadLibraryA("dbgcore.dll");
    if (handle == nullptr)
    {
        std::cout << "Failed to load dbgcore.dll" << std::endl;
        return -1;
    }

    handle = LoadLibraryA("dbghelp.dll");
    if (handle == nullptr)
    {
        std::cout << "Failed to load dbghelp.dll" << std::endl;
        return -1;
    }

    handle = LoadLibraryA("dbgmodel.dll");
    if (handle == nullptr)
    {
        std::cout << "Failed to load dbgmodel.dll" << std::endl;
        return -1;
    }

    handle = LoadLibraryA("dbgeng.dll");
    if (handle == nullptr)
    {
        std::cout << "Failed to load dbgeng.dll" << std::endl;
        return -1;
    }

//    auto engHandle = GetModuleHandleA("dbgeng.dll");
//    if (handle == nullptr)
//        false;

    //    HRESULT DebugCreate(
    //    [in]  REFIID InterfaceId,
    //    [out] PVOID  *Interface
    //    );
    typedef HRESULT(__stdcall * pfunDebugCreate)(REFIID, PVOID*);
    auto DebugCreate = (pfunDebugCreate)GetProcAddress(handle, "DebugCreate");
    if (DebugCreate == nullptr)
        return -1;

    IDebugClient7* m_debugClient {nullptr};
    IDebugControl7* m_debugControl {nullptr};
    IDebugDataSpaces* m_debugDataSpaces {nullptr};
    IDebugRegisters* m_debugRegisters {nullptr};
    IDebugSymbols3* m_debugSymbols {nullptr};
    IDebugSystemObjects* m_debugSystemObjects {nullptr};

    if (const auto result = DebugCreate(__uuidof(IDebugClient7), reinterpret_cast<void**>(&m_debugClient));
            result != S_OK)
        throw std::runtime_error("Failed to create IDebugClient7");

    QUERY_DEBUG_INTERFACE(IDebugControl7, &m_debugControl);
    QUERY_DEBUG_INTERFACE(IDebugDataSpaces, &m_debugDataSpaces);
    QUERY_DEBUG_INTERFACE(IDebugRegisters, &m_debugRegisters);
    QUERY_DEBUG_INTERFACE(IDebugSymbols3, &m_debugSymbols);
    QUERY_DEBUG_INTERFACE(IDebugSystemObjects, &m_debugSystemObjects);

    if (const auto result = m_debugClient->OpenDumpFile(const_cast<char*>(argv[1]));
            result != S_OK)
    {
        std::cout << "OpenDumpFile failed" << std::endl;
        return -1;
    }

    if (m_debugControl->SetExecutionStatus(DEBUG_STATUS_GO) != S_OK)
    {
        std::cout << "DEBUG_STATUS_GO failed" << std::endl;
    }
    if (const auto wait_result = m_debugControl->WaitForEvent(0, INFINITE);
        wait_result != S_OK
    )
    {
        std::cout << "WaitForEvent failed" << std::endl;
    }
    std::cout << std::hex << ReadRegister(m_debugRegisters, "rip") << std::endl;

    if (m_debugControl->SetExecutionStatus(DEBUG_STATUS_STEP_OVER) != S_OK)
    {
        std::cout << "DEBUG_STATUS_STEP_OVER failed" << std::endl;
    }
    if (const auto wait_result = m_debugControl->WaitForEvent(0, INFINITE);
            wait_result != S_OK
            )
    {
        std::cout << "WaitForEvent failed" << std::endl;
    }
    std::cout << std::hex << ReadRegister(m_debugRegisters, "rip") << std::endl;

    if (m_debugControl->SetExecutionStatus(DEBUG_STATUS_STEP_OVER) != S_OK)
    {
        std::cout << "DEBUG_STATUS_STEP_OVER failed" << std::endl;
    }
    if (const auto wait_result = m_debugControl->WaitForEvent(0, INFINITE);
            wait_result != S_OK
            )
    {
        std::cout << "WaitForEvent failed" << std::endl;
    }
    std::cout << std::hex << ReadRegister(m_debugRegisters, "rip") << std::endl;

    if (m_debugControl->SetExecutionStatus(DEBUG_STATUS_REVERSE_STEP_OVER) != S_OK)
    {
        std::cout << "DEBUG_STATUS_REVERSE_STEP_OVER failed" << std::endl;
    }
    if (const auto wait_result = m_debugControl->WaitForEvent(0, INFINITE);
            wait_result != S_OK
            )
    {
        std::cout << "WaitForEvent failed" << std::endl;
    }
    std::cout << std::hex << ReadRegister(m_debugRegisters, "rip") << std::endl;

    if (m_debugControl->SetExecutionStatus(DEBUG_STATUS_REVERSE_STEP_OVER) != S_OK)
    {
        std::cout << "DEBUG_STATUS_REVERSE_STEP_OVER failed" << std::endl;
    }
    if (const auto wait_result = m_debugControl->WaitForEvent(0, INFINITE);
            wait_result != S_OK
            )
    {
        std::cout << "WaitForEvent failed" << std::endl;
    }
    std::cout << std::hex << ReadRegister(m_debugRegisters, "rip") << std::endl;

    if (m_debugClient->TerminateProcesses() != S_OK)
    {
        std::cout << "TerminateProcesses() failed" << std::endl;
    }
    std::cout << "final: " << std::hex << ReadRegister(m_debugRegisters, "rip") << std::endl;

    return 0;
}
