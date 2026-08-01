package run.halo.fixture;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.jackson2.SecurityJackson2Modules;

/**
 * Negative fixture (RC2): Spring Security's `enableDefaultTyping` is a
 * different symbol from `ObjectMapper#enableDefaultTyping` — it installs an
 * allow-list PolymorphicTypeValidator. JS501 must not fire on it.
 */
public class SecurityJacksonModule {

    public void configure(ObjectMapper owner) {
        SecurityJackson2Modules.enableDefaultTyping(owner);
    }
}
