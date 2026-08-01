package run.halo.fixture;

import org.springframework.beans.factory.config.YamlProcessor;
import org.springframework.core.io.Resource;

/**
 * Negative fixture (RC1): a wrapper that extends Spring's YamlProcessor, which
 * builds its Yaml with a SafeConstructor. `.load()` here can never instantiate
 * an arbitrary class, so JS501 must not fire.
 */
public class YamlSafeWrapper extends YamlProcessor {

    private final Resource resource;

    public YamlSafeWrapper(Resource resource) {
        this.resource = resource;
        setResources(resource);
    }

    public Object read() {
        YamlSafeWrapper loader = new YamlSafeWrapper(resource);
        return loader.load();
    }

    public Object readAgain() {
        return new YamlSafeWrapper(resource).load();
    }
}
