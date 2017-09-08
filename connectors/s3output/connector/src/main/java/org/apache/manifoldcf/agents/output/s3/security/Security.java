package org.apache.manifoldcf.agents.output.s3.security;

/**
 * Created by jeckep on 08.09.17.
 */
public class Security {
    private String[] tokens = null;
    private String[] denyTokens = null;

    public Security(String[] tokens, String[] denyTokens) {
        this.tokens = tokens;
        this.denyTokens = denyTokens;
    }

    public String[] getTokens() {
        return tokens;
    }

    public String[] getDenyTokens() {
        return denyTokens;
    }
}
