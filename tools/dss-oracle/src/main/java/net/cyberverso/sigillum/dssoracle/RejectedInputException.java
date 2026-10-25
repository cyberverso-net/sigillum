package net.cyberverso.sigillum.dssoracle;

import java.nio.file.Path;

/**
 * DSS cannot parse an input file. The mode records this as the result
 * {@code rejected} in {@code summary.json}, which is a result rather than a
 * failure of the tool (ADR-0013).
 */
public final class RejectedInputException extends Exception {
    private static final long serialVersionUID = 1L;

    /** The option that named the file. */
    private final String option;
    /** The file as named on the command line. */
    private final String file;

    /**
     * Creates the exception.
     *
     * @param option the option that named the file, such as {@code --timestamp}
     * @param file the file
     * @param cause the error of the DSS parser
     */
    public RejectedInputException(String option, Path file, Throwable cause) {
        super(parserMessage(cause), cause);
        this.option = option;
        this.file = file.toString();
    }

    /**
     * Returns the option that named the file.
     *
     * @return the option, such as {@code --timestamp}
     */
    public String option() {
        return option;
    }

    /**
     * Returns the file, as named on the command line.
     *
     * @return the file
     */
    public String file() {
        return file;
    }

    /** Joins the distinct messages of the error and its first causes, which DSS often wraps. */
    private static String parserMessage(Throwable cause) {
        StringBuilder message = new StringBuilder();
        int depth = 0;
        for (Throwable current = cause; current != null && depth < 8; current = current.getCause(), depth++) {
            String text = current.getMessage() == null ? current.getClass().getName() : current.getMessage();
            if (message.indexOf(text) < 0) {
                if (!message.isEmpty()) {
                    message.append(": ");
                }
                message.append(text);
            }
        }
        return message.toString();
    }
}
