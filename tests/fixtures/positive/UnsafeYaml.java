package run.halo.fixture;

import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

/**
 * Positive fixture (RC1): a real SnakeYAML Yaml built with the permissive
 * Constructor. Global type tags are accepted — JS501 must fire.
 */
public class UnsafeYaml {

    public Object parse(String text) {
        Yaml yaml = new Yaml(new Constructor(Object.class, null));
        return yaml.load(text);
    }
}
