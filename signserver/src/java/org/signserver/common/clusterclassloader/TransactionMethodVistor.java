package org.signserver.common.clusterclassloader;

import javax.persistence.EntityManager;

import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.signserver.server.annotations.Transaction;
import org.signserver.server.annotations.TransactionType;

/**
 * A Method visitor that checks a method for a transaction
 * annotation and if it exists injects transaction code.
 * 
 * @author Philip Vendil 24 okt 2008
 * @see ClusterClassLoaderUtils
 * @see TransactionMethodVistor
 * @version $Id$
 */
public class TransactionMethodVistor extends AdviceAdapter{
	
	private Label startFinally = new Label();
	private int newTransaction;
	private int transactionSuccesful;
	private int transactionType;
	private int workerEntityManager;

	public TransactionMethodVistor(MethodVisitor mv, int acc, String name, String desc) {
		super(mv,acc,name,desc);
	}
	
	public void visitCode() { 
		super.visitCode();
		if(annotationFound){
		  transactionType = newLocal(Type.getObjectType(ClusterClassLoaderUtils.getInternalObjectName(TransactionType.class.getName())));
		  newTransaction = newLocal(Type.BOOLEAN_TYPE);
		  transactionSuccesful = newLocal(Type.BOOLEAN_TYPE);					  
		  workerEntityManager = newLocal(Type.getObjectType(ClusterClassLoaderUtils.getInternalObjectName(EntityManager.class.getName())));
		  
		  mv.visitFieldInsn(GETSTATIC, ClusterClassLoaderUtils.getInternalObjectName(TransactionType.class.getName()), "SUPPORTS", ClusterClassLoaderUtils.getInternalObjectNameWithL(TransactionType.class.getName()));
		  mv.visitVarInsn(ASTORE, transactionType);					  
		  mv.visitInsn(ICONST_0);
		  mv.visitVarInsn(ISTORE, newTransaction);
		  mv.visitInsn(ICONST_0);
		  mv.visitVarInsn(ISTORE, transactionSuccesful);					  
		  mv.visitInsn(ACONST_NULL);
		  mv.visitVarInsn(ASTORE, workerEntityManager);
		  
		  mv.visitVarInsn(ALOAD, 0);
		  mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Object", "getClass", "()Ljava/lang/Class;");
		  mv.visitVarInsn(ALOAD, 0);
		  mv.visitMethodInsn(INVOKESTATIC, ClusterClassLoaderUtils.getInternalObjectName(ClusterClassLoaderUtils.class.getName()), "findWorkerEntityManager", "(Ljava/lang/Class;Ljava/lang/Object;)Ljavax/persistence/EntityManager;");
		  mv.visitVarInsn(ASTORE, workerEntityManager);
		  
		  
		  mv.visitVarInsn(ALOAD, 0);
		  mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Object", "getClass", "()Ljava/lang/Class;");
		  mv.visitVarInsn(ALOAD, 0);
		  mv.visitMethodInsn(INVOKESTATIC, ClusterClassLoaderUtils.getInternalObjectName(ClusterClassLoaderUtils.class.getName()), "findTransactionType", "(Ljava/lang/Class;Ljava/lang/Object;)"+ClusterClassLoaderUtils.getInternalObjectNameWithL(TransactionType.class.getName()));
		  mv.visitVarInsn(ASTORE, transactionType);
		  
          mv.visitLabel(startFinally);
          
          mv.visitVarInsn(ALOAD, transactionType);
          mv.visitFieldInsn(GETSTATIC, ClusterClassLoaderUtils.getInternalObjectName(TransactionType.class.getName()), "REQUIRED", ClusterClassLoaderUtils.getInternalObjectNameWithL(TransactionType.class.getName()));
          Label l8 = new Label();
          mv.visitJumpInsn(IF_ACMPNE, l8);
          mv.visitVarInsn(ALOAD, workerEntityManager);
          mv.visitMethodInsn(INVOKEINTERFACE, "javax/persistence/EntityManager", "getTransaction", "()Ljavax/persistence/EntityTransaction;");
          mv.visitMethodInsn(INVOKEINTERFACE, "javax/persistence/EntityTransaction", "isActive", "()Z");
          mv.visitJumpInsn(IFNE, l8);
          mv.visitVarInsn(ALOAD, workerEntityManager);
          mv.visitMethodInsn(INVOKEINTERFACE, "javax/persistence/EntityManager", "getTransaction", "()Ljavax/persistence/EntityTransaction;");
          mv.visitMethodInsn(INVOKEINTERFACE, "javax/persistence/EntityTransaction", "begin", "()V");
          mv.visitInsn(ICONST_1);
          mv.visitVarInsn(ISTORE, newTransaction);
          mv.visitLabel(l8);
		}
    }
	
	public void visitMaxs(int maxStack,int maxLocals) { 
		if(annotationFound){

			Label endFinally = new Label(); 
			mv.visitTryCatchBlock(startFinally, endFinally, endFinally, null); 
			mv.visitLabel(endFinally); 
			onFinally(ATHROW); 
			mv.visitInsn(ATHROW);								
			
		}
		mv.visitMaxs(maxStack, maxLocals);

	} 
	protected void onMethodExit(int opcode) { 
		if(annotationFound){
			if(opcode!=ATHROW) { 	
				mv.visitVarInsn(ILOAD, newTransaction);
				Label l14 = new Label();
				mv.visitJumpInsn(IFEQ, l14);
				mv.visitVarInsn(ALOAD, workerEntityManager);
				mv.visitMethodInsn(INVOKEINTERFACE, "javax/persistence/EntityManager", "getTransaction", "()Ljavax/persistence/EntityTransaction;");
				mv.visitMethodInsn(INVOKEINTERFACE, "javax/persistence/EntityTransaction", "commit", "()V");
				mv.visitInsn(ICONST_1);
				mv.visitVarInsn(ISTORE, transactionSuccesful);	
				mv.visitLabel(l14);

				onFinally(opcode); 
			} 
		} 
	}
	
	private void onFinally(int opcode) { 
		
		mv.visitVarInsn(ILOAD, transactionSuccesful);
		Label l19 = new Label();
		mv.visitJumpInsn(IFNE, l19);
		mv.visitVarInsn(ALOAD, workerEntityManager);
		mv.visitMethodInsn(INVOKEINTERFACE, "javax/persistence/EntityManager", "getTransaction", "()Ljavax/persistence/EntityTransaction;");
		mv.visitMethodInsn(INVOKEINTERFACE, "javax/persistence/EntityTransaction", "rollback", "()V");
		mv.visitLabel(l19);
				
	}

	private boolean annotationFound = false;
	
	public AnnotationVisitor visitAnnotation(String desc,
			boolean arg1) {
		if(desc.equals(ClusterClassLoaderUtils.getInternalObjectNameWithL(Transaction.class.getName()))){
			annotationFound= true;
		}
		return super.visitAnnotation(desc, arg1);
	}
	
}

