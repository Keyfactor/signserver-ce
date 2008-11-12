package org.signserver.common.clusterclassloader;

import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassAdapter;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;

/**
 * Helper class for the ClusterClassLoaderUtil to find
 * a Transaction annotation on methods in a class. And
 * then to insert transaction logic into it. 
 * 
 * @author Philip Vendil 24 okt 2008
 * @see ClusterClassLoaderUtils
 * @see TransactionMethodVistor
 * @version $Id$
 */
public class TransactionFinder extends ClassAdapter {

	public TransactionFinder(ClassVisitor cv) {
		super(cv);
	}
	
	public AnnotationVisitor visitAnnotation(String arg0,
			boolean arg1) {
		return super.visitAnnotation(arg0, arg1);
	}

	public MethodVisitor visitMethod(
        final int access,
        final String name,
        final String desc,
        final String signature,
        final String[] exceptions)
    {
        
        MethodVisitor v = cv.visitMethod(access,
                name,
                desc,
                signature,
                exceptions);
        
        return new TransactionMethodVistor(v,access,name,desc);
        
    }
}

