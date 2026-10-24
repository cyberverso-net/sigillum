package net.cyberverso.sigillum.dssoracle;

/** Exit codes of the tool. */
public final class ExitCodes {
    /** The run succeeded. */
    public static final int SUCCESS = 0;
    /** The tool failed. */
    public static final int FAILURE = 1;
    /** The command line is not valid. */
    public static final int USAGE = 2;
    /** The mode is not implemented yet. */
    public static final int NOT_IMPLEMENTED = 3;
    /** Network access was attempted. */
    public static final int NETWORK_ACCESS = 4;

    private ExitCodes() {
    }
}
