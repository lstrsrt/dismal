#include "dismal.hh"

using code_t = dismal::u8[];
using dismal::decoder;
using dismal::insn;

static void disasm_stream(decoder& dc, code_t code, size_t n)
{
    size_t off{};
    insn ins{};
    while (off < n) {
        ins = dc.disasm(code + off);
        dc.insn2str(ins);
        off += ins.length;
        if (ins.flags & dismal::insn_err)
            __debugbreak();
    }
}

int main()
{
    decoder dc{};
    code_t code = {
        // Just some meaningless example code
        0x8b, 0x4d, 0x0c,              // mov ecx, [ebp+0xc]
        0x83, 0xc1, 0x20,              // add ecx, 0x20
        0x0f, 0xb6, 0xc0,              // movzx eax, al
        0x85, 0xc0,                    // test eax, eax
        0xc1, 0xeb, 0x03,              // shr ebx, 0x3
        0x0f, 0xba, 0xea, 0x14,        // bts edx, 0x14
        0xf8,                          // clc
        0x2c, 0x06,                    // sub al, 0x6
        0x53,                          // push ebx
        0x3d, 0x78, 0x56, 0x34, 0x12,  // cmp eax, 0x12345678
        0x66, 0x49,                    // dec cx
        0x8b, 0x4c, 0x58, 0x04         // mov ecx, [eax+ebx*2+0x4]
    };
    disasm_stream(dc, code, std::size(code));
}
