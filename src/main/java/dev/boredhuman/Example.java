package dev.boredhuman;

public class Example {

	public static void main(String[] args) {
		String[] attachArgs = new String[]{"load", "instrument", "false", "C:/somedirectory/javagent.jar"};
		Attach attach = new Attach(attachArgs);

		attach.enumProcesses((name, handle, id) -> {
			if (id == 1337) {
				attach.invokeJVM_EnqueueOperation(handle, id, null);
				return true;
			}
			return false;
		});
	}
}
