/***************************************************************************
    qgsauthawsssomethod.h
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

#ifndef QGISAUTHAWSSSOMETHOD_H
#define QGISAUTHAWSSSOMETHOD_H

#include <QObject>
#include <QMutex>

#include "qgsauthconfig.h"
#include "qgsauthmethod.h"
#include "qgsauthmethodmetadata.h"

class QWidget;

class QgsAuthAwsSsoMethod : public QgsAuthMethod
{
    Q_OBJECT

  public:

    static const QString AUTH_METHOD_KEY;
    static const QString AUTH_METHOD_DESCRIPTION;
    static const QString AUTH_METHOD_DISPLAY_DESCRIPTION;

    explicit QgsAuthAwsSsoMethod();

    // QgsAuthMethod interface
    QString key() const override;

    QString description() const override;

    QString displayDescription() const override;

    bool updateNetworkRequest( QNetworkRequest &request, const QString &authcfg,
                               const QString &dataprovider = QString() ) override;

    bool updateDataSourceUriItems( QStringList &connectionItems, const QString &authcfg,
                                   const QString &dataprovider = QString() ) override;


    bool updateNetworkProxy( QNetworkProxy &proxy, const QString &authcfg,
                             const QString &dataprovider = QString() ) override;

    void clearCachedConfig( const QString &authcfg ) override;

    void updateMethodConfig( QgsAuthMethodConfig &mconfig ) override;

#ifdef HAVE_GUI
    QWidget *editWidget( QWidget *parent )const override;
#endif

  private:
    QgsAuthMethodConfig getMethodConfig( const QString &authcfg, bool fullconfig = true );

    void putMethodConfig( const QString &authcfg, const QgsAuthMethodConfig &mconfig );

    void removeMethodConfig( const QString &authcfg );

    QString escapeUserPass( const QString &val, QChar delim = '\'' ) const;

    static QMap<QString, QgsAuthMethodConfig> sAuthConfigCache;
};

class QgsAuthAwsSsoMethodMetadata : public QgsAuthMethodMetadata
{
  public:
    QgsAuthAwsSsoMethodMetadata()
      : QgsAuthMethodMetadata( QgsAuthAwsSsoMethod::AUTH_METHOD_KEY, QgsAuthAwsSsoMethod::AUTH_METHOD_DESCRIPTION )
    {}
    QgsAuthAwsSsoMethod *createAuthMethod() const override {return new QgsAuthAwsSsoMethod;}
    //QStringList supportedDataProviders() const override;
};

#endif // QGISAUTHAWSSSOMETHOD_H
