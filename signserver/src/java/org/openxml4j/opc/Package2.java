package org.openxml4j.opc;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.opc.Package;
import org.openxml4j.opc.PackageAccess;
import org.openxml4j.opc.PackagePart;
import org.openxml4j.opc.PackagePartName;
import org.openxml4j.opc.ZipPackage;

public class Package2 extends Package {

	protected Package2(PackageAccess access) {
		super(access);
		// TODO Auto-generated constructor stub
	}

	@Override
	protected void closeImpl() throws IOException {
		// TODO Auto-generated method stub

	}

	@Override
	protected PackagePart createPartImpl(PackagePartName partName,
			String contentType, boolean loadRelationships) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected void flushImpl() {
		// TODO Auto-generated method stub

	}

	@Override
	protected PackagePart getPartImpl(PackagePartName partName) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected PackagePart[] getPartsImpl() throws InvalidFormatException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected void removePartImpl(PackagePartName partName) {
		// TODO Auto-generated method stub

	}

	@Override
	protected void revertImpl() {
		// TODO Auto-generated method stub

	}

	@Override
	protected void saveImpl(OutputStream outputStream) throws IOException {
		// TODO Auto-generated method stub

	}

	/**
	 * value added method to ooxml4j
	 * 
	 * @param in
	 * @param access
	 * @return
	 * @throws InvalidFormatException
	 * @throws IOException
	 */
	public static Package open(InputStream in, PackageAccess access)
			throws InvalidFormatException, IOException {
		Package pack = new ZipPackage(in, access);
		pack.getParts();
		return pack;
	}

}
