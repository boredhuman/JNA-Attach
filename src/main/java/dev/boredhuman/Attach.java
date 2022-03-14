package dev.boredhuman;

import com.sun.jna.Function;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.PointerByReference;

public class Attach {

	static final int PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFFF;
	static final int TOKEN_ADJUST_PRIVILEGES = 0x20;
	static final int WOW64_CONTEXT_ALL = 0x1003F;

	NativeLibrary psapi = NativeLibrary.getInstance("Psapi");
	NativeLibrary kernel32 = NativeLibrary.getInstance("kernel32");
	NativeLibrary advapi32 = NativeLibrary.getInstance("advapi32.dll");

	Function getEnumProcesses = this.psapi.getFunction("EnumProcesses");
	Function openProcess = this.kernel32.getFunction("OpenProcess");
	Function queryFullProcessImageNameA = this.kernel32.getFunction("QueryFullProcessImageNameA");
	Function getLastError = this.kernel32.getFunction("GetLastError");
	Function closeHandle = this.kernel32.getFunction("CloseHandle");
	Function enumProcessModules = this.kernel32.getFunction("K32EnumProcessModules");
	Function getModuleFileName = this.kernel32.getFunction("K32GetModuleFileNameExA");
	Function getCurrentProcess = this.kernel32.getFunction("GetCurrentProcess");
	Function openProcessToken = this.kernel32.getFunction("OpenProcessToken");

	Function lookupPrivilegeValue = this.advapi32.getFunction("LookupPrivilegeValueA");
	Function adjustTokenPrivileges = this.advapi32.getFunction("AdjustTokenPrivileges");

	Function virtualAllocEx = this.kernel32.getFunction("VirtualAllocEx");
	Function writeProcessMemory = this.kernel32.getFunction("WriteProcessMemory");
	Function createNamedPipe = this.kernel32.getFunction("CreateNamedPipeA");
	Function createRemoteThread = this.kernel32.getFunction("CreateRemoteThread");
	Function getThreadId = this.kernel32.getFunction("GetThreadId");
	Function getThreadContext = this.kernel32.getFunction("GetThreadContext");
	Function resumeThread = this.kernel32.getFunction("ResumeThread");
	Function debugActiveProcess = this.kernel32.getFunction("DebugActiveProcess");
	Function debugActiveProcessStop = this.kernel32.getFunction("DebugActiveProcessStop");
	Function waitForDebugEvent = this.kernel32.getFunction("WaitForDebugEvent");
	Function readProcessMemory = this.kernel32.getFunction("ReadProcessMemory");
	Function continueDebugEvent = this.kernel32.getFunction("ContinueDebugEvent");
	Function waitForSingleObject = this.kernel32.getFunction("WaitForSingleObject");
	Function setThreadContext = this.kernel32.getFunction("SetThreadContext");
	Function loadLibrary = this.kernel32.getFunction("LoadLibraryExA");
	Function getProcAddress = this.kernel32.getFunction("GetProcAddress");
	Function freeLibrary = this.kernel32.getFunction("FreeLibrary");
	Function virtualFree = this.kernel32.getFunction("VirtualFreeEx");
	Function disconnectNamedPipe = this.kernel32.getFunction("DisconnectNamedPipe");

	String[] args;

	public Attach(String[] args) {
		this.args = args;
		this.getDebugPrivileges();
	}

	public void getDebugPrivileges() {
		Pointer hProcess = (Pointer) this.getCurrentProcess.invoke(Pointer.class, null);
		LongByReference hToken = new LongByReference();
		int status = (int) this.openProcessToken.invoke(int.class, new Object[] {hProcess, Attach.TOKEN_ADJUST_PRIVILEGES, hToken});

		if (status == 0) {
			System.out.println("Failed to open process token error " + this.getLastError());
		} else {
			LongByReference luidMem = new LongByReference();

			Memory privilegeName = new Memory("SeDebugPrivilege".length() + 1);
			privilegeName.setString(0, "SeDebugPrivilege");

			status = (int) this.lookupPrivilegeValue.invoke(int.class, new Object[] {null, privilegeName, luidMem});

			if (status == 0) {
				System.out.println("Failed to get privilege name error" + this.getLastError());
			}

			Memory tokenPrivileges = new Memory(16);

			tokenPrivileges.setInt(0, 1);
			tokenPrivileges.setLong(4, luidMem.getValue());
			tokenPrivileges.setInt(12, 2); // SE_PRIVILEGE_ENABLED

			status = (int) this.adjustTokenPrivileges.invoke(int.class, new Object[] {hToken.getValue(), 0, tokenPrivileges, 16, 0, 0});

			if (status == 0) {
				System.out.println("Failed to adjust token privileges error " + this.getLastError());
			}
		}

		this.closeHandle.invoke(new Object[] {hToken.getValue()});
	}

	public void enumProcesses(EnumProcessCallback callback) {
		Memory processList = new Memory(1024 * 4);
		IntByReference bytesRead = new IntByReference();
		processList.getPointer(0);

		int status = (int) this.getEnumProcesses.invoke(int.class, new Object[] {processList, processList.size(), bytesRead});

		if (status == 0) {
			System.out.println("Failed to enum processes");
		}

		Memory processNamePtr = new Memory(260);
		int processesCount = bytesRead.getValue() / 4;

		for (int i = 0; i < processesCount; i++) {
			int processID = processList.getInt(i * 4L);

			Pointer handle = (Pointer) this.openProcess.invoke(Pointer.class, new Object[]{Attach.PROCESS_ALL_ACCESS, false, processID});

			if (handle == null) {
				System.out.println("Failed to get handle for " + processID + " error " + this.getLastError());
				continue;
			}

			processNamePtr.clear(260);

			status = (int) this.queryFullProcessImageNameA.invoke(int.class, new Object[] {handle, 0, processNamePtr, new IntByReference(260)});
			// this is normally true if the process is a system process
			if (status == 0) {
				System.out.println("Failed to get process name error: " + this.getLastError());
				this.closeHandle.invoke(new Object[] {handle});
				continue;
			}

			String processNameString = Attach.getString(processNamePtr);

			boolean exit = callback.accept(processNameString, handle, processID);

			this.closeHandle.invoke(new Object[] {handle});

			if (exit) {
				break;
			}
		}

		Native.free(Pointer.nativeValue(processNamePtr));
		Native.free(Pointer.nativeValue(processList));
	}

	public void invokeJVM_EnqueueOperation(Pointer processHandle, int processID, PipeHandler pipeHandler) {
		Memory processModules = new Memory(1024 * 8);
		IntByReference bytesWritten = new IntByReference();

		int status = (int) this.enumProcessModules.invoke(int.class, new Object[] {processHandle, processModules, processModules.size(), bytesWritten});

		if (status == 0) {
			System.out.println("Failed to enum process modules error: " + this.getLastError());
		}

		Memory moduleNamePtr = new Memory(260);
		int moduleCount = bytesWritten.getValue() / 8;

		for (int i = 0; i < moduleCount; i++) {

			Pointer hModule = processModules.getPointer(i * 8L);

			moduleNamePtr.clear(260);
			status = (int) this.getModuleFileName.invoke(int.class, new Object[] {processHandle, hModule, moduleNamePtr, 260});

			if (status == 0) {
				System.out.println("Failed to get module name error: " + this.getLastError());
			}

			String moduleName = Attach.getString(moduleNamePtr);

			if (!moduleName.contains("jvm.dll")) {
				continue;
			}
			// get offset of jvm_enqueue operation relative to base address of jvm dll
			Pointer jvmStart = (Pointer) this.loadLibrary.invoke(Pointer.class, new Object[] {moduleNamePtr, 0, 1}); // DONT_RESOLVE_DLL_REFERENCES

			Memory procName = new Memory(260);
			procName.setString(0, "JVM_EnqueueOperation");

			Pointer targetFunctionAddress = (Pointer) this.getProcAddress.invoke(Pointer.class, new Object[] {jvmStart, procName});

			this.freeLibrary.invoke(new Object[] {jvmStart});

			Native.free(Pointer.nativeValue(procName));

			long offset = Pointer.nativeValue(targetFunctionAddress) - Pointer.nativeValue(jvmStart);

			long actualAddress = Pointer.nativeValue(hModule) + offset;

			Pointer load = this.allocWriteString(processHandle, this.args[0]);
			Pointer instrument = this.allocWriteString(processHandle, this.args[1]);
			Pointer relativePath = this.allocWriteString(processHandle, this.args[2]);
			Pointer jarLocation = this.allocWriteString(processHandle, this.args[3]);

			Memory pipeName = new Memory(260);
			pipeName.setString(0, "\\\\.\\pipe\\javatool" + System.currentTimeMillis());

			Pointer hPipe = (Pointer) this.createNamedPipe.invoke(Pointer.class, new Object[] {pipeName, 1, 0, 1, 4096, 8192, 0, 0});

			Pointer pipe = this.allocWriteString(processHandle, Attach.getString(pipeName));

			Native.free(Pointer.nativeValue(pipeName));

			// create thread suspended
			Pointer thread = (Pointer) this.createRemoteThread.invoke(Pointer.class, new Object[] {processHandle, 0, 0, actualAddress, load, 4, 0});

			int threadID = (int) this.getThreadId.invoke(int.class, new Object[] {thread});

			Memory context = new Memory(1232);

			// set context flags
			context.setInt(48, Attach.WOW64_CONTEXT_ALL);

			status = (int) this.getThreadContext.invoke(int.class, new Object[] {thread, context});

			if (status == 0) {
				System.out.println("Failed to get thread context error " + this.getLastError());
			}
			// set hardware breakpoint on jvm enqueue operation using dr0
			context.setLong(72, actualAddress);
			// set flags in dr7
			context.setLong(112, 1 | 2);
			// start debugging process
			status = (int) this.debugActiveProcess.invoke(int.class, new Object[] {processID});

			if (status == 0) {
				System.out.println("Could not debug process error " + this.getLastError());
			}

			status = (int) this.setThreadContext.invoke(int.class, new Object[] {thread, context});

			if (status == 0) {
				System.out.println("Could not set thread context error " + this.getLastError());
			}

			status = (int) this.resumeThread.invoke(int.class, new Object[] {thread});

			if (status == -1) {
				System.out.println("Failed to resume thread error " + this.getLastError());
			}

			Memory debugEvent = new Memory(176);

			while (true) {
				this.waitForDebugEvent.invoke(new Object[] {debugEvent, 0xFFFFFFFF});

				int dwDebugEventCode = debugEvent.getInt(0);
				int dwProcessID = debugEvent.getInt(4);
				int dwThreadID = debugEvent.getInt(8);

				if (dwDebugEventCode == 1 && dwThreadID == threadID) {
					status = (int) this.getThreadContext.invoke(int.class, new Object[] {thread, context});

					if (status == 0) {
						System.out.println("Failed to get thread context error " + this.getLastError());
					}

					context.setLong(72, 0);
					context.setLong(112, 0);
					// pass our args
					// rcx
					context.setLong(128, Pointer.nativeValue(load));
					// rdx
					context.setLong(136, Pointer.nativeValue(instrument));
					// r8
					context.setLong(184, Pointer.nativeValue(relativePath));
					// r9
					context.setLong(192, Pointer.nativeValue(jarLocation));

					Pointer stackPointer = context.getPointer(152);
					LongByReference stackValue = new LongByReference();

					status = (int) this.readProcessMemory.invoke(int.class, new Object[] {processHandle, stackPointer, stackValue, 8, 0});

					if (status == 0) {
						System.out.println("Failed to read value in the stack pointer error " + this.getLastError());
					}
					// make stack bigger
					long rsp = context.getLong(152) - 8;
					context.setLong(152, rsp);

					// write return address to stack pointer
					status = (int) this.writeProcessMemory.invoke(int.class, new Object[] {processHandle, rsp, stackValue, 8, 0});

					if (status == 0) {
						System.out.println("Failed to write stack value into new stack address error " + this.getLastError());
					}

					// write pipe address into stack
					status = (int) this.writeProcessMemory.invoke(int.class, new Object[] {processHandle, rsp + 40, new PointerByReference(pipe), 8, 0});

					if (status == 0) {
						System.out.println("Failed to write stack value into new stack address error " + this.getLastError());
					}

					status = (int) this.setThreadContext.invoke(int.class, new Object[] {thread, context});

					if (status == 0) {
						System.out.println("Failed to set thread context with new params error " + this.getLastError());
					}
					// DBG_EXCEPTION_HANDLED
					this.continueDebugEvent.invoke(new Object[] {dwProcessID, dwThreadID, 0x00010001});
					break;
				} else {
					// DBG_EXCEPTION_NOT_HANDLED
					this.continueDebugEvent.invoke(new Object[] {dwProcessID, dwThreadID, 0x80010001});
				}
			}

			status = (int) this.debugActiveProcessStop.invoke(int.class, new Object[] {processID});

			if (status == 0) {
				System.out.println("Failed to stop debugger error " + this.getLastError());
			}

			this.waitForSingleObject.invoke(new Object[] {thread, 0xFFFFFFFF});
			this.closeHandle.invoke(new Object[] {thread});

			this.virtualFree.invoke(new Object[] {processHandle, load, 0, 0x00008000}); // MEM_RELEASE
			this.virtualFree.invoke(new Object[] {processHandle, instrument, 0, 0x00008000}); // MEM_RELEASE
			this.virtualFree.invoke(new Object[] {processHandle, relativePath, 0, 0x00008000}); // MEM_RELEASE
			this.virtualFree.invoke(new Object[] {processHandle, jarLocation, 0, 0x00008000}); // MEM_RELEASE
			this.virtualFree.invoke(new Object[] {processHandle, pipe, 0, 0x00008000}); // MEM_RELEASE

			if (pipeHandler == null) {
				this.disconnectNamedPipe.invoke(new Object[]{hPipe});
			} else {
				pipeHandler.handlePipe(hPipe);
			}

			Native.free(Pointer.nativeValue(debugEvent));
			Native.free(Pointer.nativeValue(context));

			break;
		}

		Native.free(Pointer.nativeValue(processModules));
	}

	public Pointer allocWriteString(Pointer processHandle, String string) {

		byte[] data = string.getBytes();
		Memory stringMemory = new Memory(data.length);
		stringMemory.write(0, data, 0, data.length);

		// plus 1 more null termination
		Pointer pointer =  (Pointer) this.virtualAllocEx.invoke(Pointer.class, new Object[] {processHandle, 0, stringMemory.size() + 1, 0x1000, 0x4}); // MEM_COMMIT PAGE_READWRITE

		if (pointer != null) {
			int status = (int) this.writeProcessMemory.invoke(int.class, new Object[] {processHandle, pointer, stringMemory, stringMemory.size(), 0});
			if (status == 0) {
				System.out.println("Failed to write process memory error: " + this.getLastError());
			}
		}

		Native.free(Pointer.nativeValue(stringMemory));

		return pointer;
	}

	public int getLastError() {
		return (int) this.getLastError.invoke(int.class, null);
	}

	public interface PipeHandler {
		void handlePipe(Pointer hPipe);
	}

	public interface EnumProcessCallback {
		// return true to stop enumerating
		boolean accept(String processFileLocation, Pointer processHandle, int processID);
	}

	public static String getString(Memory stringMemory) {
		byte[] stringBytes = stringMemory.getByteArray(0, (int) stringMemory.size());

		StringBuilder cString = new StringBuilder();

		int j = 0;
		while (j < stringMemory.size()) {
			byte stringByte = stringBytes[j];
			if (stringByte == 0) {
				break;
			}
			cString.append((char) stringByte);
			j++;
		}

		return cString.toString();
	}
}
