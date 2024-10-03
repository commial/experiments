"use strict";

// 0: no-op
// 1: kp -> k
// 2: no symbol reload
const FAST = 1;

// undefined: output to console
// filename: output to filename
//const LOG = "c:\\output.log";
const LOG = undefined;
var g_logFile;
var g_textWriter;

var cur_call_recurs = [];

function log_write(line) {
    if (g_textWriter !== undefined)
        g_textWriter.Write(line);
    else
        host.diagnostics.debugLog(line);
}

function current_indent() {
    var i = 0;
    for (var elt of cur_call_recurs) {
        if (elt.skip)
            continue;
        i += 1;
    }
    return i;
}

let logln = function (e) {
    for (var line of e.split("\n")) {
        for (var i = 0; i < current_indent(); i++) {
            log_write("|  ")
        }
        log_write(line + '\n');
    }
}

function initializeScript()
{
    return [new host.apiVersionSupport(1, 6)];
}

function RunCommands(cmd)
{
    var ctl = host.namespace.Debugger.Utility.Control;   
    var output = ctl.ExecuteCommand(cmd);

    for (var line of output)
    {
        logln(line);
    }
}

const i64  = x => host.parseInt64(x);
const  u8 = x => host.memory.readMemoryValues(x, 1, 1)[0];
const u16 = x => host.memory.readMemoryValues(x, 1, 2)[0];
const u32 = x => host.memory.readMemoryValues(x, 1, 4)[0];
const u64 = x => host.memory.readMemoryValues(x, 1, 8)[0];
const hex  = x => x.toString(16);
function IsKd() { return host.namespace.Debugger.Sessions.First().Attributes.Target.IsKernelTarget === true; }
const system = x => host.namespace.Debugger.Utility.Control.ExecuteCommand(x);

function $(r){ return IsKd() ? host.namespace.Debugger.State.DebuggerVariables.curthread.Registers.User[r] || host.namespace.Debugger.State.DebuggerVariables.curthread.Registers.Kernel[r] : host.namespace.Debugger.State.DebuggerVariables.curthread.Registers.User[r]; }
const FIELD_OFFSET = (t, n) => parseInt( system(`?? #FIELD_OFFSET(${t}, ${n})`).First().split(" ")[1].replace("0n", "") );
const CONTAINING_RECORD = (a, t, n) => a.add(-FIELD_OFFSET(t, n));

const PORT_MESSAGE_SIZE = 0x28;

const unpack_u32_le = x => (x.charCodeAt(0)) | (x.charCodeAt(1) << 8) | (x.charCodeAt(2) << 16) | (x.charCodeAt(3) << 24);
const hexdump_inline = x => x.split("")
     .map(c => c.charCodeAt(0).toString(16).padStart(2, "0"))
     .join("");

function hexdump(buffer, blockSize) {
    blockSize = blockSize || 16;
    var lines = [];
    var hex = "0123456789ABCDEF";
    for (var b = 0; b < buffer.length; b += blockSize) {
        var block = buffer.slice(b, Math.min(b + blockSize, buffer.length));
        var addr = ("0000" + b.toString(16)).slice(-4);
        var codes = block.split('').map(function (ch) {
            var code = ch.charCodeAt(0);
            return " " + hex[(0xF0 & code) >> 4] + hex[0x0F & code];
        }).join("");
        codes += "   ".repeat(blockSize - block.length);
        var chars = block.replace(/[\x00-\x1F\x20]/g, '.');
        chars +=  " ".repeat(blockSize - block.length);
        lines.push(addr + " " + codes + "  " + chars);
    }
    return lines.join("\n");
}

function read_multibytes(addr, length) {
    // TODO: catch error
    return String.fromCharCode.apply(null, host.memory.readMemoryValues(addr, length, 1));
}

function stack_dump() {
    let cmd = "kp";
    if (FAST > 0)
        cmd = "k";
    var ctl = host.namespace.Debugger.Utility.Control;
    let UNK_SYMB_RE = /\s\s0x000/g;
    var output = ctl.ExecuteCommand(cmd);

    var reload_needed = false;
    for (var line of output)
    {
        if (FAST > 1)
            break;
        if (UNK_SYMB_RE.exec(line)) {
            logln("[DEBUG] RELOADING USER SYMBOL")
            ctl.ExecuteCommand(".reload /user");
            reload_needed = true;
            break;
        }
    }

    if (reload_needed) {
        output = ctl.ExecuteCommand(cmd);
    }
    for (var line of output)
    {
        logln(line);
    }
}

class AlpcHandle {
    constructor(Name) {
        this.Name = Name;
    }
}

const CONNPORT_RE = /\s+ConnectionPort\s+:\s+[a-f0-9]+\s+\(([^\)]+)\)/g;

function alpcHandleInfo(handle) {
    var alpcObj = host.createTypedObject(handle.Object.Body.targetLocation, "nt", "_ALPC_PORT");
    var port_name = "UNKNOWN_PORT_NAME";
    // hackish way to get the port name
    /*
    var ctl = host.namespace.Debugger.Utility.Control;   
    var output = ctl.ExecuteCommand("!alpc /p " + handle.Object.Body.targetLocation);
    
    for (var line of output)
    {
        let rez = CONNPORT_RE.exec(line);
        if (rez !== null) {
            port_name = rez[1];
        }
    }
    */

    let conn_port = alpcObj.CommunicationInfo.ConnectionPort;
    let conn_port_obj_hdr = host.createTypedObject(CONTAINING_RECORD(conn_port.targetLocation, "nt!_OBJECT_HEADER", "Body"), "nt", "_OBJECT_HEADER");
    // Get the port name, based on "!alpc" implementation
    // Use the InfoMask and nt!ObpInfoMaskToOffset, on the ConnectionPort
    /*
    0x01	nt!_OBJECT_HEADER_CREATOR_INFO
    0x02	nt!_OBJECT_HEADER_NAME_INFO
    0x04	nt!_OBJECT_HEADER_HANDLE_INFO
    0x08	nt!_OBJECT_HEADER_QUOTA_INFO
    0x10	nt!_OBJECT_HEADER_PROCESS_INFO
    */
    switch(conn_port_obj_hdr.InfoMask & 3) {
        case 0:
        case 1:
            // nt!_OBJECT_HEADER_NAME_INFO is not set
            port_name = "UNKNOWN_PORT_NAME";
            break;
        case 2:
        case 3:
            let header_name = host.createTypedObject(conn_port_obj_hdr.targetLocation.add(-0x20), "nt", "_OBJECT_HEADER_NAME_INFO");
            port_name = header_name.Name.toString();
            port_name = port_name.substr(1, port_name.length - 2);
    }

    let owner = conn_port.OwnerProcess;
    let owner_str = host.memory.readString(owner.ImageFileName.targetLocation) + "(" + owner.UniqueProcessId.address + ")";
    let client = alpcObj.CommunicationInfo.ClientCommunicationPort.targetLocation;
    let client_str = "";
    if (client == 0) {
        client_str = "NO CLIENT";
    } else {
        let cli_proc = alpcObj.CommunicationInfo.ClientCommunicationPort.OwnerProcess;
        client_str = host.memory.readString(cli_proc.ImageFileName.targetLocation) + "(" + cli_proc.UniqueProcessId.address + ")";
    }
    logln("Handle: " + hex(handle.Handle) + " Port: " + port_name + " | " + client_str + " -> " + owner_str);
    return new AlpcHandle(port_name);
}

function refreshHandles(process) {
    logln("Process " + process.Name + "(" + process.Id + ")");
 
        // And each handle in every process
        var handles = process.Io.Handles;
 
        // Note that an exception can be raised while looping over the handles
        // (e.g. an empty handle table)
        try {
 
            for (var handle of handles) {
                if (handle.Type == "ALPC Port") {
                    alpcHandleInfo(handle);
                }
            }
        } catch (e) {
 
            logln("[ERROR] Exception parsing handle table!\n");
 
        }
}

function listALPC() {
    // Loop over each process
    var processes = host.currentSession.Processes; 
    for (var process of processes) {
        refreshHandles(process);
    } 
}

class BPInfo {
    constructor(skip, send_msg) {
        this.skip = skip;
        this.sendMessage = send_msg;
    }
}

function logskip(msg) {
    logln("[SKIP] " + msg);
    cur_call_recurs.push(new BPInfo(true, undefined));
    return false;
}

function hexdumpmsg(msg){
    if (msg == i64(0))
        return false;

    // We have a message!
    let Msg = host.createPointerObject(msg, "nt", "_PORT_MESSAGE*");
    let data_len = Msg.u1.s1.DataLength;
    if (data_len == 0) {
        return false;
    }

    // There is data in the message
    let data = read_multibytes(msg.add(PORT_MESSAGE_SIZE), data_len);
    let rpc_type = unpack_u32_le(data.slice(0, 4));
    // Parsing based on hakril.github.io/PythonForWindows
    switch(rpc_type) {
        case 0:
        // RPC CALL
        let req_id = unpack_u32_le(data.slice(0x0c, 0x10));
        let method = unpack_u32_le(data.slice(0x14, 0x18));
        logln("CALL req_id:" + req_id + " method:" + method);
        break;
        case 1:
        // RPC BIND / BIND_OK
        let target = data.slice(12, 12+0x10);
        let vers = data.charCodeAt(0x1C);
        logln("BIND to " + hexdump_inline(target) + " (" + vers + ")");
        break;
        case 2:
        // RPC_RESPONSE_TYPE_FAIL
        logln("FAIL");
        break;
        case 3:
        // RPC_RESPONSE_TYPE_SUCCESS
        req_id = unpack_u32_le(data.slice(0x0c, 0x10));
        logln("SUCCESS req_id:" + req_id);
        break;
        default:
        logln("UNKNOWN REQUEST TYPE");
    }
    logln(hexdump(data));

    return true;
}

function handle_bp() {
    // ntlpcapi.h
    /*
    NTSYSCALLAPI
    NTSTATUS
    NTAPI
    NtAlpcSendWaitReceivePort(
        __in HANDLE PortHandle,
        __in ULONG Flags,
        __in_opt PPORT_MESSAGE SendMessage,
        __in_opt PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
        __inout_opt PPORT_MESSAGE ReceiveMessage,
        __inout_opt PULONG BufferLength,
        __inout_opt PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
        __in_opt PLARGE_INTEGER Timeout
    );
    */
    logln("[SendWait] Start");
    if (["MpCmdRun.exe", "MsMpEng.exe"].includes(host.currentProcess.Name)) {
        return logskip("Process " + host.currentProcess.Name);
    }

    logln(host.currentProcess.Name + "(" + host.currentProcess.Id + ")");
    let handle = $("rcx"); // PortHandle
    let sendmsg = $("r8"); // SendMessage
    let recvmsg = u64($("rbp").add(0x28)); // ReceiveMessage
    logln("PortHandle=" + hex(handle) + ", SendMessage=" + hex(sendmsg) + ", ReceiveMessage=" + hex(recvmsg));
    //let recvmsg = u64($("rbp").add(0x28)); // ReceiveMessage
    if (handle.compareTo(0xffffffff00000000) < 0) {
        let port_name = alpcHandleInfo(host.currentProcess.Io.Handles[handle]).Name;
        if (port_name.startsWith("CoreMessag")) {
            return logskip("CoreMessage");
        }
    }
    if (sendmsg == i64(0)) {
        return logskip("no send msg");
    }
    cur_call_recurs.push(new BPInfo(false, sendmsg));
    if (!hexdumpmsg(sendmsg)){
        return false;
    }
    // We have a message!
    stack_dump();

    return false;
}

function handle_bp_out() {
    // Call just before ret
    // rbp is SendMessage
    let bpinfo = cur_call_recurs.pop();
    logln("[SendWait] Ret");
    if (bpinfo === undefined) {
        // We might have began inside a call
        return false;
    }

    if (bpinfo.skip)
        return false;

    if (!hexdumpmsg(bpinfo.sendMessage))
        return false;
    
    return false;
}

const MAX_CHECk_RET = 100;
function findRet(start_addr)
{
    var ctl = host.namespace.Debugger.Utility.Control;
    let RET_RE = /\sret/g;
    let cur_addr = start_addr;
    for (let i = 0; i < MAX_CHECk_RET; i++) {
        var output = ctl.ExecuteCommand("u " + cur_addr);
        for (var line of output)
        {
            if(RET_RE.exec(line)) {
                return line.split(" ")[0]
            }
        }
        cur_addr = line.split(" ")[0]
    }
    throw "Unable to find ret";
}

function invokeScript()
{
    let Control = host.namespace.Debugger.Utility.Control;
    let CurrentProcess = host.currentProcess;
    let NtAlpcSendReceive = host.getModuleSymbolAddress('nt', 'NtAlpcSendWaitReceivePort');
    let BreakpointAlreadySet = CurrentProcess.Debug.Breakpoints.Any(
        c => c.Address == NtAlpcSendReceive
    );
    if(BreakpointAlreadySet == false) {
        logln('NtAlpcSendReceive @ ' + NtAlpcSendReceive.toString(16));
        Control.ExecuteCommand('bp /w "@$scriptContents.handle_bp()" ' + NtAlpcSendReceive.toString(16));
        let bp_out_addr = findRet("nt!NtAlpcSendWaitReceivePort");
        logln('NtAlpcSendReceive out @ ' + bp_out_addr);
        Control.ExecuteCommand('bp /w "@$scriptContents.handle_bp_out()" ' + bp_out_addr);
    } else {
        logln('Breakpoint already set.');
    }
    logln('Press "g" to run the target.');

    if (LOG !== undefined) {
        if (host.namespace.Debugger.Utility.FileSystem.FileExists(LOG)) {        
            g_logFile = host.namespace.Debugger.Utility.FileSystem.CreateFile(LOG, "OpenExisting");
        }
        else {        
            g_logFile = host.namespace.Debugger.Utility.FileSystem.CreateFile(LOG);
        }

        g_textWriter = host.namespace.Debugger.Utility.FileSystem.CreateTextWriter(g_logFile, "Utf16");
        host.diagnostics.debugLog("Logging to " + LOG + "\nUse 'dx @$scriptContents.g_logFile.Close()' to close the log file\n");
    }

    //RunCommands("dx @$curprocess.Name");
}
