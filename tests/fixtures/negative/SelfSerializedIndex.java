package run.halo.search;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Path;

/**
 * Trust-source fixture (RC4): the class writes its own objects to an on-disk
 * index and reads them back. JS501 must still report the dangerous API, but at
 * LOW severity with a LOCAL_FS source — poisoning the stream requires local
 * write access first.
 */
public class SelfSerializedIndex {

    private final Path indexFile;

    public SelfSerializedIndex(Path indexFile) {
        this.indexFile = indexFile;
    }

    public void save(Object state) throws Exception {
        try (ObjectOutputStream out =
                new ObjectOutputStream(new FileOutputStream(indexFile.toFile()))) {
            out.writeObject(state);
        }
    }

    public Object restore() throws Exception {
        try (ObjectInputStream in =
                new ObjectInputStream(new FileInputStream(indexFile.toFile()))) {
            return in.readObject();
        }
    }
}
