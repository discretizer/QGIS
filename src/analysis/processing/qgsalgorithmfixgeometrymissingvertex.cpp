/***************************************************************************
                        qgsalgorithmfixgeometrymissingvertex.cpp
                        ---------------------
   begin                : June 2024
   copyright            : (C) 2024 by Jacky Volpes
   email                : jacky dot volpes at oslandia dot com
***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include "qgsalgorithmfixgeometrymissingvertex.h"
#include "qgsgeometrycheckcontext.h"
#include "qgsgeometrymissingvertexcheck.h"
#include "qgsvectordataproviderfeaturepool.h"
#include "qgsgeometrycheckerror.h"
#include "qgsvectorfilewriter.h"

///@cond PRIVATE

QString QgsFixGeometryMissingVertexAlgorithm::name() const
{
  return QStringLiteral( "fixgeometrymissingvertex" );
}

QString QgsFixGeometryMissingVertexAlgorithm::displayName() const
{
  return QObject::tr( "Add missing vertices along borders" );
}

QString QgsFixGeometryMissingVertexAlgorithm::shortDescription() const
{
  return QObject::tr( "Add missing vertices along borders detected with the \"Missing vertices along borders\" algorithm from the \"Check geometry\" section" );
}

QStringList QgsFixGeometryMissingVertexAlgorithm::tags() const
{
  return QObject::tr( "fix,missing,vertex,polygons" ).split( ',' );
}

QString QgsFixGeometryMissingVertexAlgorithm::group() const
{
  return QObject::tr( "Fix geometry" );
}

QString QgsFixGeometryMissingVertexAlgorithm::groupId() const
{
  return QStringLiteral( "fixgeometry" );
}

QString QgsFixGeometryMissingVertexAlgorithm::shortHelpString() const
{
  return QObject::tr( "This algorithm adds the missing vertices along polygons borders, "
                      "based on an error layer from the \"Missing vertices along borders\" algorithm in the \"Check geometry\" section." );
}

QgsFixGeometryMissingVertexAlgorithm *QgsFixGeometryMissingVertexAlgorithm::createInstance() const
{
  return new QgsFixGeometryMissingVertexAlgorithm();
}

void QgsFixGeometryMissingVertexAlgorithm::initAlgorithm( const QVariantMap &configuration )
{
  Q_UNUSED( configuration )

  // Inputs
  addParameter( new QgsProcessingParameterFeatureSource(
    QStringLiteral( "INPUT" ), QObject::tr( "Input layer" ), QList<int>() << static_cast<int>( Qgis::ProcessingSourceType::VectorPolygon )
  ) );
  addParameter( new QgsProcessingParameterFeatureSource(
    QStringLiteral( "ERRORS" ), QObject::tr( "Error layer" ), QList<int>() << static_cast<int>( Qgis::ProcessingSourceType::VectorPoint )
  ) );

  addParameter( new QgsProcessingParameterField(
    QStringLiteral( "UNIQUE_ID" ), QObject::tr( "Field of original feature unique identifier" ),
    QStringLiteral( "id" ), QStringLiteral( "ERRORS" )
  ) );
  addParameter( new QgsProcessingParameterField(
    QStringLiteral( "PART_IDX" ), QObject::tr( "Field of part index" ),
    QStringLiteral( "gc_partidx" ), QStringLiteral( "ERRORS" ),
    Qgis::ProcessingFieldParameterDataType::Numeric
  ) );
  addParameter( new QgsProcessingParameterField(
    QStringLiteral( "RING_IDX" ), QObject::tr( "Field of ring index" ),
    QStringLiteral( "gc_ringidx" ), QStringLiteral( "ERRORS" ),
    Qgis::ProcessingFieldParameterDataType::Numeric
  ) );
  addParameter( new QgsProcessingParameterField(
    QStringLiteral( "VERTEX_IDX" ), QObject::tr( "Field of vertex index" ),
    QStringLiteral( "gc_vertidx" ), QStringLiteral( "ERRORS" ),
    Qgis::ProcessingFieldParameterDataType::Numeric
  ) );

  // Outputs
  addParameter( new QgsProcessingParameterFeatureSink(
    QStringLiteral( "OUTPUT" ), QObject::tr( "Border vertices fixed layer" ), Qgis::ProcessingSourceType::VectorPolygon
  ) );
  addParameter( new QgsProcessingParameterFeatureSink(
    QStringLiteral( "REPORT" ), QObject::tr( "Report layer from fixing border vertices" ), Qgis::ProcessingSourceType::VectorPoint
  ) );

  std::unique_ptr<QgsProcessingParameterNumber> tolerance = std::make_unique<QgsProcessingParameterNumber>(
    QStringLiteral( "TOLERANCE" ), QObject::tr( "Tolerance" ), Qgis::ProcessingNumberParameterType::Integer, 8, false, 1, 13
  );
  tolerance->setFlags( tolerance->flags() | Qgis::ProcessingParameterFlag::Advanced );
  tolerance->setHelp( QObject::tr( "The \"Tolerance\" advanced parameter defines the numerical precision of geometric operations, "
                                   "given as an integer n, meaning that any difference smaller than 10⁻ⁿ (in map units) is considered zero." ) );
  addParameter( tolerance.release() );
}

QVariantMap QgsFixGeometryMissingVertexAlgorithm::processAlgorithm( const QVariantMap &parameters, QgsProcessingContext &context, QgsProcessingFeedback *feedback )
{
  const std::unique_ptr<QgsProcessingFeatureSource> input( parameterAsSource( parameters, QStringLiteral( "INPUT" ), context ) );
  if ( !input )
    throw QgsProcessingException( invalidSourceError( parameters, QStringLiteral( "INPUT" ) ) );

  const std::unique_ptr<QgsProcessingFeatureSource> errors( parameterAsSource( parameters, QStringLiteral( "ERRORS" ), context ) );
  if ( !errors )
    throw QgsProcessingException( invalidSourceError( parameters, QStringLiteral( "ERRORS" ) ) );

  QgsProcessingMultiStepFeedback multiStepFeedback( 2, feedback );

  const QString featIdFieldName = parameterAsString( parameters, QStringLiteral( "UNIQUE_ID" ), context );
  const QString partIdxFieldName = parameterAsString( parameters, QStringLiteral( "PART_IDX" ), context );
  const QString ringIdxFieldName = parameterAsString( parameters, QStringLiteral( "RING_IDX" ), context );
  const QString vertexIdxFieldName = parameterAsString( parameters, QStringLiteral( "VERTEX_IDX" ), context );

  // Verify that input fields exists
  if ( errors->fields().indexFromName( featIdFieldName ) == -1 )
    throw QgsProcessingException( QObject::tr( "Field %1 does not exist in the error layer." ).arg( featIdFieldName ) );
  if ( errors->fields().indexFromName( partIdxFieldName ) == -1 )
    throw QgsProcessingException( QObject::tr( "Field %1 does not exist in the error layer." ).arg( partIdxFieldName ) );
  if ( errors->fields().indexFromName( ringIdxFieldName ) == -1 )
    throw QgsProcessingException( QObject::tr( "Field %1 does not exist in the error layer." ).arg( ringIdxFieldName ) );
  if ( errors->fields().indexFromName( vertexIdxFieldName ) == -1 )
    throw QgsProcessingException( QObject::tr( "Field %1 does not exist in the error layer." ).arg( vertexIdxFieldName ) );
  int inputIdFieldIndex = input->fields().indexFromName( featIdFieldName );
  if ( inputIdFieldIndex == -1 )
    throw QgsProcessingException( QObject::tr( "Field %1 does not exist in input layer." ).arg( featIdFieldName ) );

  QgsField inputFeatIdField = input->fields().at( inputIdFieldIndex );
  if ( inputFeatIdField.type() != errors->fields().at( errors->fields().indexFromName( featIdFieldName ) ).type() )
    throw QgsProcessingException( QObject::tr( "Field %1 does not have the same type as in the error layer." ).arg( featIdFieldName ) );

  QString dest_output;
  const std::unique_ptr<QgsFeatureSink> sink_output( parameterAsSink(
    parameters, QStringLiteral( "OUTPUT" ), context, dest_output, input->fields(), input->wkbType(), input->sourceCrs()
  ) );
  if ( !sink_output )
    throw QgsProcessingException( invalidSinkError( parameters, QStringLiteral( "OUTPUT" ) ) );

  QString dest_report;
  QgsFields reportFields = errors->fields();
  reportFields.append( QgsField( QStringLiteral( "report" ), QMetaType::QString ) );
  reportFields.append( QgsField( QStringLiteral( "error_fixed" ), QMetaType::Bool ) );
  const std::unique_ptr<QgsFeatureSink> sink_report( parameterAsSink(
    parameters, QStringLiteral( "REPORT" ), context, dest_report, reportFields, errors->wkbType(), errors->sourceCrs()
  ) );
  if ( !sink_report )
    throw QgsProcessingException( invalidSinkError( parameters, QStringLiteral( "REPORT" ) ) );

  const QgsProject *project = QgsProject::instance();
  QgsGeometryCheckContext checkContext = QgsGeometryCheckContext( mTolerance, input->sourceCrs(), project->transformContext(), project );
  QStringList messages;

  const QgsGeometryMissingVertexCheck check( &checkContext, QVariantMap() );

  std::unique_ptr<QgsVectorLayer> fixedLayer( input->materialize( QgsFeatureRequest() ) );
  QgsVectorDataProviderFeaturePool featurePool = QgsVectorDataProviderFeaturePool( fixedLayer.get(), false );
  QMap<QString, QgsFeaturePool *> featurePools;
  featurePools.insert( fixedLayer->id(), &featurePool );

  QgsFeature errorFeature, inputFeature, testDuplicateIdFeature;
  QgsFeatureIterator errorFeaturesIt = errors->getFeatures();
  QList<QgsGeometryCheck::Changes> changesList;
  QgsFeature reportFeature;
  reportFeature.setFields( reportFields );
  long long progression = 0;
  long long totalProgression = errors->featureCount();
  multiStepFeedback.setCurrentStep( 1 );
  multiStepFeedback.setProgressText( QObject::tr( "Fixing errors..." ) );
  while ( errorFeaturesIt.nextFeature( errorFeature ) )
  {
    if ( feedback->isCanceled() )
      break;

    progression++;
    multiStepFeedback.setProgress( static_cast<double>( static_cast<long double>( progression ) / totalProgression ) * 100 );
    reportFeature.setGeometry( errorFeature.geometry() );

    QVariant attr = errorFeature.attribute( featIdFieldName );
    if ( !attr.isValid() || attr.isNull() )
      throw QgsProcessingException( QObject::tr( "NULL or invalid value found in unique field %1" ).arg( featIdFieldName ) );

    QString idValue = errorFeature.attribute( featIdFieldName ).toString();
    if ( inputFeatIdField.type() == QMetaType::QString )
      idValue = "'" + idValue + "'";

    QgsFeatureIterator it = fixedLayer->getFeatures( QgsFeatureRequest().setFilterExpression( "\"" + featIdFieldName + "\" = " + idValue ) );
    if ( !it.nextFeature( inputFeature ) || !inputFeature.isValid() )
      reportFeature.setAttributes( errorFeature.attributes() << QObject::tr( "Source feature not found or invalid" ) << false );

    else if ( it.nextFeature( testDuplicateIdFeature ) )
      throw QgsProcessingException( QObject::tr( "More than one feature found in input layer with value %1 in unique field %2" ).arg( idValue ).arg( featIdFieldName ) );

    else if ( inputFeature.geometry().isNull() )
      reportFeature.setAttributes( errorFeature.attributes() << QObject::tr( "Feature geometry is null" ) << false );

    else
    {
      QgsGeometryCheckError checkError = QgsGeometryCheckError(
        &check,
        QgsGeometryCheckerUtils::LayerFeature( &featurePool, inputFeature, &checkContext, false ),
        errorFeature.geometry().asPoint(),
        QgsVertexId(
          errorFeature.attribute( partIdxFieldName ).toInt(),
          errorFeature.attribute( ringIdxFieldName ).toInt(),
          errorFeature.attribute( vertexIdxFieldName ).toInt()
        )
      );
      for ( QgsGeometryCheck::Changes changes : changesList )
        checkError.handleChanges( changes );

      QgsGeometryCheck::Changes changes;
      check.fixError( featurePools, &checkError, QgsGeometryMissingVertexCheck::ResolutionMethod::AddMissingVertex, QMap<QString, int>(), changes );
      changesList << changes;

      QString resolutionMessage = checkError.resolutionMessage();
      if ( checkError.status() == QgsGeometryCheckError::StatusObsolete )
        resolutionMessage = QObject::tr( "Error is obsolete" );

      reportFeature.setAttributes( errorFeature.attributes() << resolutionMessage << ( checkError.status() == QgsGeometryCheckError::StatusFixed ) );
    }

    if ( !sink_report->addFeature( reportFeature, QgsFeatureSink::FastInsert ) )
      throw QgsProcessingException( writeFeatureError( sink_report.get(), parameters, QStringLiteral( "REPORT" ) ) );
  }
  multiStepFeedback.setProgress( 100 );

  progression = 0;
  totalProgression = fixedLayer->featureCount();
  multiStepFeedback.setCurrentStep( 2 );
  multiStepFeedback.setProgressText( QObject::tr( "Exporting fixed layer..." ) );
  QgsFeature fixedFeature;
  QgsFeatureIterator fixedFeaturesIt = fixedLayer->getFeatures();
  while ( fixedFeaturesIt.nextFeature( fixedFeature ) )
  {
    if ( feedback->isCanceled() )
      break;

    progression++;
    multiStepFeedback.setProgress( static_cast<double>( progression ) / static_cast<double>( totalProgression ) * 100 );
    if ( !sink_output->addFeature( fixedFeature, QgsFeatureSink::FastInsert ) )
      throw QgsProcessingException( writeFeatureError( sink_output.get(), parameters, QStringLiteral( "OUTPUT" ) ) );
  }
  multiStepFeedback.setProgress( 100 );

  QVariantMap outputs;
  outputs.insert( QStringLiteral( "OUTPUT" ), dest_output );
  outputs.insert( QStringLiteral( "REPORT" ), dest_report );

  return outputs;
}

bool QgsFixGeometryMissingVertexAlgorithm::prepareAlgorithm( const QVariantMap &parameters, QgsProcessingContext &context, QgsProcessingFeedback * )
{
  mTolerance = parameterAsInt( parameters, QStringLiteral( "TOLERANCE" ), context );

  return true;
}

Qgis::ProcessingAlgorithmFlags QgsFixGeometryMissingVertexAlgorithm::flags() const
{
  return QgsProcessingAlgorithm::flags() | Qgis::ProcessingAlgorithmFlag::NoThreading;
}

///@endcond
