package org.demo.auth.srv.jwk;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

import org.springframework.jdbc.core.ArgumentPreparedStatementSetter;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.jdbc.support.lob.DefaultLobHandler;
import org.springframework.jdbc.support.lob.LobCreator;
import org.springframework.jdbc.support.lob.LobHandler;
import org.springframework.util.Assert;
import org.springframework.util.Base64Utils;
import org.springframework.util.StringUtils;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

public class JdbcJWKSource<C extends SecurityContext> implements JWKSource<C> {

	private static final String TABLE_NAME = "OAUTH2_KEY_PAIR";

	private static final String COLUMN_NAMES = "id, private_key_value, public_key_value ";

	private static final String LOAD_KEY_PAIR_SQL = "SELECT " + COLUMN_NAMES + " FROM " + TABLE_NAME + " WHERE ";

	private static final String PK_FILTER = "ID = ?";

	private static final String SAVE_KEY_PAIR_SQL = "INSERT INTO " + TABLE_NAME + " (" + COLUMN_NAMES
			+ ") VALUES (?, ?, ?)";

	private String keyId;

	private JdbcOperations jdbcOperations;

	private volatile ImmutableJWKSet<SecurityContext> immutableJWKSet;

	private LobHandler lobHandler;

	private JwkKeyPairParametersMapper jwkKeyPairParametersMapper;

	private JwkKeyPairRowMapper jwkKeyPairRowMapper;

	private static Map<String, ColumnMetadata> columnMetadataMap;

	private static ColumnMetadata getColumnMetadata(JdbcOperations jdbcOperations, String columnName,
			int defaultDataType) {
		Integer dataType = jdbcOperations.execute((ConnectionCallback<Integer>) conn -> {
			DatabaseMetaData databaseMetaData = conn.getMetaData();
			ResultSet rs = databaseMetaData.getColumns(null, null, TABLE_NAME, columnName);
			if (rs.next()) {
				return rs.getInt("DATA_TYPE");
			}
			// NOTE: (Applies to HSQL)
			// When a database object is created with one of the CREATE statements or
			// renamed with the ALTER statement,
			// if the name is enclosed in double quotes, the exact name is used as the
			// case-normal form.
			// But if it is not enclosed in double quotes,
			// the name is converted to uppercase and this uppercase version is stored in
			// the database as the case-normal form.
			rs = databaseMetaData.getColumns(null, null, TABLE_NAME.toUpperCase(), columnName.toUpperCase());
			if (rs.next()) {
				return rs.getInt("DATA_TYPE");
			}
			return null;
		});
		return new ColumnMetadata(columnName, dataType != null ? dataType : defaultDataType);
	}

	private static void initColumnMetadata(JdbcOperations jdbcOperations) {
		columnMetadataMap = new HashMap<>();
		ColumnMetadata columnMetadata;
		columnMetadata = getColumnMetadata(jdbcOperations, "private_key_value", Types.BLOB);
		columnMetadataMap.put(columnMetadata.getColumnName(), columnMetadata);
		columnMetadata = getColumnMetadata(jdbcOperations, "public_key_value", Types.BLOB);
		columnMetadataMap.put(columnMetadata.getColumnName(), columnMetadata);
	}

	public JdbcJWKSource(String keyId, JdbcOperations jdbcOperations) {
		this.keyId = keyId;
		this.jdbcOperations = jdbcOperations;
		lobHandler = new DefaultLobHandler();
		initColumnMetadata(jdbcOperations);
		jwkKeyPairParametersMapper = new JwkKeyPairParametersMapper();
		this.jwkKeyPairRowMapper = new JwkKeyPairRowMapper();
	}

	@Override
	public List<JWK> get(JWKSelector jwkSelector, C context) throws KeySourceException {
		if (Objects.isNull(immutableJWKSet)) {
			synchronized (this) {
				if (Objects.isNull(immutableJWKSet)) {
					initJWKSet();
				}
			}
		}
		return immutableJWKSet.get(jwkSelector, context);
	}

	private static KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

	private void initJWKSet() {
		JwkKeyPair jwkKeyPair = this.findById(keyId);
		if (Objects.isNull(jwkKeyPair)) {
			KeyPair keyPair = generateRsaKey();
			RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
			RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
			RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(keyId).build();
			JWKSet jwkSet = new JWKSet(rsaKey);
			this.immutableJWKSet = new ImmutableJWKSet<>(jwkSet);
			// TO SAVE

			jwkKeyPair = new JwkKeyPair();
			jwkKeyPair.setId(keyId);
			jwkKeyPair.setPrivateKey(Base64Utils.encodeToString(privateKey.getEncoded()));
			jwkKeyPair.setPublicKey(Base64Utils.encodeToString(publicKey.getEncoded()));
			insert(jwkKeyPair);

		} else {
			try {
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				byte[] privateKeyBytes = Base64Utils.decodeFromString(jwkKeyPair.getPrivateKey());
				PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
				RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8EncodedKeySpec);

				byte[] publicKeyBytes = Base64Utils.decodeFromString(jwkKeyPair.getPublicKey());
				X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyBytes);
				RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(x509EncodedKeySpec);
				RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(keyId).build();
				JWKSet jwkSet = new JWKSet(rsaKey);
				this.immutableJWKSet = new ImmutableJWKSet<>(jwkSet);
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	private class JwkKeyPairParametersMapper implements Function<JwkKeyPair, List<SqlParameterValue>> {

		@Override
		public List<SqlParameterValue> apply(JwkKeyPair keyPair) {
			List<SqlParameterValue> parameters = new ArrayList<>();
			parameters.add(new SqlParameterValue(Types.VARCHAR, keyPair.getId()));
			parameters.add(mapToSqlParameter("private_key_value", keyPair.getPrivateKey()));
			parameters.add(mapToSqlParameter("public_key_value", keyPair.getPublicKey()));
			return parameters;
		}

		private SqlParameterValue mapToSqlParameter(String columnName, String value) {
			ColumnMetadata columnMetadata = columnMetadataMap.get(columnName);
			return Types.BLOB == columnMetadata.getDataType() && StringUtils.hasText(value)
					? new SqlParameterValue(Types.BLOB, value.getBytes(StandardCharsets.UTF_8))
					: new SqlParameterValue(columnMetadata.getDataType(), value);
		}
	}

	private void insert(JwkKeyPair jwkKeyPair) {
		List<SqlParameterValue> parameters = this.jwkKeyPairParametersMapper.apply(jwkKeyPair);
		try (LobCreator lobCreator = this.lobHandler.getLobCreator()) {
			PreparedStatementSetter pss = new LobCreatorArgumentPreparedStatementSetter(lobCreator,
					parameters.toArray());
			this.jdbcOperations.update(SAVE_KEY_PAIR_SQL, pss);
		}
	}

	public JwkKeyPair findById(String id) {
		Assert.hasText(id, "id cannot be empty");
		List<SqlParameterValue> parameters = new ArrayList<>();
		parameters.add(new SqlParameterValue(Types.VARCHAR, id));
		return findBy(PK_FILTER, parameters);
	}

	private JwkKeyPair findBy(String filter, List<SqlParameterValue> parameters) {
		try (LobCreator lobCreator = getLobHandler().getLobCreator()) {
			PreparedStatementSetter pss = new LobCreatorArgumentPreparedStatementSetter(lobCreator,
					parameters.toArray());
			List<JwkKeyPair> result = getJdbcOperations().query(LOAD_KEY_PAIR_SQL + filter, pss,
					getJwkKeyPairRowMapper());
			return !result.isEmpty() ? result.get(0) : null;
		}
	}

	public JwkKeyPairRowMapper getJwkKeyPairRowMapper() {
		return jwkKeyPairRowMapper;
	}

	private JdbcOperations getJdbcOperations() {
		return this.jdbcOperations;
	}

	private LobHandler getLobHandler() {
		return this.lobHandler;
	}

	private class JwkKeyPairRowMapper implements RowMapper<JwkKeyPair> {

		@Override
		public JwkKeyPair mapRow(ResultSet rs, int rowNum) throws SQLException {
			JwkKeyPair keyPair = new JwkKeyPair();
			String id = rs.getString("id");
			String privateKey = getLobValue(rs, "private_key_value");
			String publicKey = getLobValue(rs, "public_key_value");
			keyPair.setId(id);
			keyPair.setPrivateKey(privateKey);
			keyPair.setPublicKey(publicKey);
			return keyPair;
		}

		private String getLobValue(ResultSet rs, String columnName) throws SQLException {
			String columnValue = null;
			ColumnMetadata columnMetadata = columnMetadataMap.get(columnName);
			if (Types.BLOB == columnMetadata.getDataType()) {
				byte[] columnValueBytes = lobHandler.getBlobAsBytes(rs, columnName);
				if (columnValueBytes != null) {
					columnValue = new String(columnValueBytes, StandardCharsets.UTF_8);
				}
			} else if (Types.CLOB == columnMetadata.getDataType()) {
				columnValue = lobHandler.getClobAsString(rs, columnName);
			} else {
				columnValue = rs.getString(columnName);
			}
			return columnValue;
		}

	}

	private static final class ColumnMetadata {
		private final String columnName;
		private final int dataType;

		private ColumnMetadata(String columnName, int dataType) {
			this.columnName = columnName;
			this.dataType = dataType;
		}

		private String getColumnName() {
			return this.columnName;
		}

		private int getDataType() {
			return this.dataType;
		}

	}

	private static final class LobCreatorArgumentPreparedStatementSetter extends ArgumentPreparedStatementSetter {
		private final LobCreator lobCreator;

		private LobCreatorArgumentPreparedStatementSetter(LobCreator lobCreator, Object[] args) {
			super(args);
			this.lobCreator = lobCreator;
		}

		@Override
		protected void doSetValue(PreparedStatement ps, int parameterPosition, Object argValue) throws SQLException {
			if (argValue instanceof SqlParameterValue) {
				SqlParameterValue paramValue = (SqlParameterValue) argValue;
				if (paramValue.getSqlType() == Types.BLOB) {
					if (paramValue.getValue() != null) {
						Assert.isInstanceOf(byte[].class, paramValue.getValue(),
								"Value of blob parameter must be byte[]");
					}
					byte[] valueBytes = (byte[]) paramValue.getValue();
					this.lobCreator.setBlobAsBytes(ps, parameterPosition, valueBytes);
					return;
				}
				if (paramValue.getSqlType() == Types.CLOB) {
					if (paramValue.getValue() != null) {
						Assert.isInstanceOf(String.class, paramValue.getValue(),
								"Value of clob parameter must be String");
					}
					String valueString = (String) paramValue.getValue();
					this.lobCreator.setClobAsString(ps, parameterPosition, valueString);
					return;
				}
			}
			super.doSetValue(ps, parameterPosition, argValue);
		}

	}

}
