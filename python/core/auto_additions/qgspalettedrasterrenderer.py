# The following has been generated automatically from src/core/raster/qgspalettedrasterrenderer.h
try:
    QgsPalettedRasterRenderer.Class.__attribute_docs__ = {'value': 'Value', 'color': 'Color to render value', 'label': 'Label for value'}
    QgsPalettedRasterRenderer.Class.__annotations__ = {'value': float, 'color': 'QColor', 'label': str}
    QgsPalettedRasterRenderer.Class.__doc__ = """Properties of a single value class"""
    QgsPalettedRasterRenderer.Class.__group__ = ['raster']
except (NameError, AttributeError):
    pass
try:
    QgsPalettedRasterRenderer.MultiValueClass.__attribute_docs__ = {'values': 'Values', 'color': 'Color to render values', 'label': 'Label for values'}
    QgsPalettedRasterRenderer.MultiValueClass.__annotations__ = {'values': 'List[object]', 'color': 'QColor', 'label': str}
    QgsPalettedRasterRenderer.MultiValueClass.__group__ = ['raster']
except (NameError, AttributeError):
    pass
try:
    QgsPalettedRasterRenderer.create = staticmethod(QgsPalettedRasterRenderer.create)
    QgsPalettedRasterRenderer.colorTableToClassData = staticmethod(QgsPalettedRasterRenderer.colorTableToClassData)
    QgsPalettedRasterRenderer.rasterAttributeTableToClassData = staticmethod(QgsPalettedRasterRenderer.rasterAttributeTableToClassData)
    QgsPalettedRasterRenderer.classDataFromString = staticmethod(QgsPalettedRasterRenderer.classDataFromString)
    QgsPalettedRasterRenderer.classDataFromFile = staticmethod(QgsPalettedRasterRenderer.classDataFromFile)
    QgsPalettedRasterRenderer.classDataToString = staticmethod(QgsPalettedRasterRenderer.classDataToString)
    QgsPalettedRasterRenderer.classDataFromRaster = staticmethod(QgsPalettedRasterRenderer.classDataFromRaster)
    QgsPalettedRasterRenderer.__overridden_methods__ = ['clone', 'flags', 'block', 'canCreateRasterAttributeTable', 'inputBand', 'setInputBand', 'writeXml', 'legendSymbologyItems', 'createLegendNodes', 'usesBands', 'toSld', 'accept']
    QgsPalettedRasterRenderer.__group__ = ['raster']
except (NameError, AttributeError):
    pass
