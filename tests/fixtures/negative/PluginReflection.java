package run.halo.plugin;

import org.pf4j.PluginWrapper;

/**
 * Trust-source fixture (RC4): the class name comes from an installed plugin's
 * own extension list. JS702 must still report, but tagged PLUGIN so the
 * severity reflects that the input is already-trusted code.
 */
public class PluginReflection {

    public Object instantiate(PluginWrapper pluginWrapper, String extensionClassName)
            throws Exception {
        ClassLoader loader = pluginWrapper.getPluginClassLoader();
        Class<?> extensionClass = loader.loadClass(extensionClassName);
        return extensionClass.getDeclaredConstructor().newInstance();
    }
}
