/***************************************************************************
    qgsauthawsssomethod.cpp
    ---------------------
    begin                : September 2, 2023
    author               : Aaron Dalton
    email                : aadalton at vt dot edu
 ***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include "qgsauthmanager.h"
#include "qgslogger.h"
#include "qgsapplication.h"

#ifdef HAVE_GUI
#include "qgsauthawsssoedit.h"
#endif


const QString QgsAuthAwsSsoMethod::AUTH_METHOD_KEY = QStringLiteral( "AWSSSO" );
const QString QgsAuthAwsSsoMethod::AUTH_METHOD_DESCRIPTION = QStringLiteral( "AWS SSO" );
const QString QgsAuthAwsSsoMethod::AUTH_METHOD_DISPLAY_DESCRIPTION = tr( "AWS SSO" );

QMap<QString, QgsAuthMethodConfig> QgsAuthAwsSsoMethod::sAuthConfigCache = QMap<QString, QgsAuthMethodConfig>();

QgsAuthAwsSsoMethod::QgsAuthAwsSsoMethod()
{
  setVersion( 1 );
  setExpansions( QgsAuthMethod::NetworkRequest );
  setDataProviders( QStringList() 
    << QStringLiteral( "awss3" )
    << QStringLiteral( "postgresql"));
}

QString QgsAuthAwsSsoMethod::key() const
{
  return AUTH_METHOD_KEY;
}

QString QgsAuthAwsSsoMethod::description() const
{
  return AUTH_METHOD_DESCRIPTION;
}

QString QgsAuthAwsSsoMethod::displayDescription() const
{
  return AUTH_METHOD_DISPLAY_DESCRIPTION;
}

bool QgsAuthAwsSsoMethod::updateNetworkRequest( QNetworkRequest &request, const QString &authcfg,
    const QString &dataprovider )
{
    if (dataprovider == QStringLiteral("awss3")) {

    }
  const QgsAuthMethodConfig config = getMethodConfig( authcfg );
  if ( !config.isValid() )
  {
    QgsDebugError( QStringLiteral( "Update request config FAILED for authcfg: %1: config invalid" ).arg( authcfg ) );
    return false;
  }

  const QByteArray username = config.config( QStringLiteral( "username" ) ).toLocal8Bit();
  const QByteArray password = config.config( QStringLiteral( "password" ) ).toLocal8Bit();
  const QByteArray region = config.config( QStringLiteral( "region" ) ).toLocal8Bit();

  const QByteArray headerList = "host;x-amz-content-sha256;x-amz-date";
  const QByteArray encryptionMethod = "AWS4-HMAC-SHA256";
  const QDateTime currentDateTime = QDateTime::currentDateTime().toUTC();
  const QByteArray date = currentDateTime.toString( "yyyyMMdd" ).toLocal8Bit();
  const QByteArray dateTime = currentDateTime.toString( "yyyyMMddThhmmssZ" ).toLocal8Bit();

  QByteArray canonicalPath = QUrl::toPercentEncoding( request.url().path(), "/" );  // Don't encode slash
  if ( canonicalPath.isEmpty() )
  {
    canonicalPath = "/";
  }

  QByteArray method;
  QByteArray payloadHash;
  if ( request.hasRawHeader( "X-Amz-Content-SHA256" ) )
  {
    method = "PUT";
    payloadHash = request.rawHeader( "X-Amz-Content-SHA256" );
  }
  else
  {
    method = "GET";
    payloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";  // Sha256 of empty payload
    request.setRawHeader( QByteArray( "X-Amz-Content-SHA256" ), payloadHash );
  }

  const QByteArray canonicalRequest = method + '\n' +
                                      canonicalPath + '\n' +
                                      '\n' +
                                      "host:" + request.url().host().toLocal8Bit() + '\n' +
                                      "x-amz-content-sha256:" + payloadHash + '\n' +
                                      "x-amz-date:" + dateTime + '\n' +
                                      '\n' +
                                      headerList + '\n' +
                                      payloadHash;

  const QByteArray canonicalRequestHash = QCryptographicHash::hash( canonicalRequest, QCryptographicHash::Sha256 ).toHex();
  const QByteArray stringToSign = encryptionMethod + '\n' +
                                  dateTime + '\n' +
                                  date + "/" + region + "/s3/aws4_request" + '\n' +
                                  canonicalRequestHash;

  const QByteArray signingKey = QMessageAuthenticationCode::hash( "aws4_request",
                                QMessageAuthenticationCode::hash( "s3",
                                    QMessageAuthenticationCode::hash( region,
                                        QMessageAuthenticationCode::hash( date, "AWS4" + password,
                                            QCryptographicHash::Sha256 ),
                                        QCryptographicHash::Sha256 ),
                                    QCryptographicHash::Sha256 ),
                                QCryptographicHash::Sha256 );

  const QByteArray signature = QMessageAuthenticationCode::hash( stringToSign, signingKey, QCryptographicHash::Sha256 ).toHex();

  request.setRawHeader( QByteArray( "Host" ), request.url().host().toLocal8Bit() );
  request.setRawHeader( QByteArray( "X-Amz-Date" ), dateTime );
  request.setRawHeader( QByteArray( "Authorization" ),
                        encryptionMethod + "Credential=" + username + '/' + date + "/" + region + "/s3/aws4_request, SignedHeaders=" + headerList + ", Signature=" + signature );

  return true;
}

void QgsAuthAwsSsoMethod::clearCachedConfig( const QString &authcfg )
{
  removeMethodConfig( authcfg );
}

void QgsAuthAwsSsoMethod::updateMethodConfig( QgsAuthMethodConfig &mconfig )
{
  Q_UNUSED( mconfig );
  // NOTE: add updates as method version() increases due to config storage changes
}

QgsAuthMethodConfig QgsAuthAwsSsoMethod::getMethodConfig( const QString &authcfg, bool fullconfig )
{
  const QMutexLocker locker( &mMutex );
  QgsAuthMethodConfig config;

  // check if it is cached
  if ( sAuthConfigCache.contains( authcfg ) )
  {
    config = sAuthConfigCache.value( authcfg );
    QgsDebugMsgLevel( QStringLiteral( "Retrieved config for authcfg: %1" ).arg( authcfg ), 2 );
    return config;
  }

  // else build bundle
  if ( !QgsApplication::authManager()->loadAuthenticationConfig( authcfg, config, fullconfig ) )
  {
    QgsDebugMsgLevel( QStringLiteral( "Retrieved config for authcfg: %1" ).arg( authcfg ), 2 );
    return QgsAuthMethodConfig();
  }

  // cache bundle
  putMethodConfig( authcfg, config );

  return config;
}

void QgsAuthAwsSsoMethod::putMethodConfig( const QString &authcfg, const QgsAuthMethodConfig &mconfig )
{
  const QMutexLocker locker( &mMutex );
  QgsDebugMsgLevel( QStringLiteral( "Putting AWS SSO config for authcfg: %1" ).arg( authcfg ), 2 );
  sAuthConfigCache.insert( authcfg, mconfig );
}

void QgsAuthAwsSsoMethod::removeMethodConfig( const QString &authcfg )
{
  const QMutexLocker locker( &mMutex );
  if ( sAuthConfigCache.contains( authcfg ) )
  {
    sAuthConfigCache.remove( authcfg );
    QgsDebugMsgLevel( QStringLiteral( "Removed Aws SSO config for authcfg: %1" ).arg( authcfg ), 2 );
  }
}

#ifdef HAVE_GUI
QWidget *QgsAuthAwsSsoMethod::editWidget( QWidget *parent ) const
{
  return new QgsAuthAwsS3Edit( parent );
}
#endif

//////////////////////////////////////////////
// Plugin externals
//////////////////////////////////////////////


#ifndef HAVE_STATIC_PROVIDERS
QGISEXTERN QgsAuthMethodMetadata *authMethodMetadataFactory()
{
  return new QgsAuthAwsSsoMethodMetadata();
}
#endif
