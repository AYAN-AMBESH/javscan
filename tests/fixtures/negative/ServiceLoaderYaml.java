package fixtures;

import org.yaml.snakeyaml.Yaml;
import java.io.Reader;
import java.util.Map;
import java.util.ServiceLoader;

/**
 * JS501 — a file that imports SnakeYAML must not make every `.load(...)` in it
 * a Yaml load. `ServiceLoader.load(...)` is a static call on a different class.
 */
public class ServiceLoaderYaml {

    public Map<String, Object> fromYaml(Reader reader) {
        return new Yaml().load(reader);
    }

    public void fromSpi() {
        for (Runnable r : ServiceLoader.load(Runnable.class)) {
            r.run();
        }
    }
}
