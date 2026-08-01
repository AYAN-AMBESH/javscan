package run.halo.fixture;

import org.springframework.core.io.Resource;
import run.halo.app.infra.utils.YamlUnstructuredLoader;

/**
 * Negative fixture (RC1, cross-file): the exact shape of the Halo call sites.
 * `YamlUnstructuredLoader` is declared in another compilation unit, so javscan
 * cannot see that it extends YamlProcessor — but it can see the receiver is
 * not `org.yaml.snakeyaml.Yaml`, and the file does not import SnakeYAML at
 * all. That is enough to suppress: matching the bare `.load()` name is what
 * produced all five false positives.
 */
public class CrossFileYamlWrapper {

    public Object fromResource(Resource resource) {
        return new YamlUnstructuredLoader(resource).load();
    }

    public Object fromField(YamlUnstructuredLoader yamlUnstructuredLoader) {
        return yamlUnstructuredLoader.load();
    }

    public Object fromLocal(Resource resource) {
        YamlUnstructuredLoader loader = new YamlUnstructuredLoader(resource);
        return loader.load();
    }
}
