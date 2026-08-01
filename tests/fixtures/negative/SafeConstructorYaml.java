package run.halo.fixture;

import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.LoaderOptions;

/**
 * Negative fixture (RC1): a real SnakeYAML Yaml, but constructed with a
 * SafeConstructor. Global type tags are rejected, so JS501 must not fire.
 */
public class SafeConstructorYaml {

    public Object parse(String text) {
        Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
        return yaml.load(text);
    }
}
