from lexi.config import RESOURCES, SCORER_PATH_TEMPLATE
from lexi.core.simplification.lexical import *


def fresh_train(userId="default", language="da", resources=None):
    scorer = LexiScorer.staticload(SCORER_PATH_TEMPLATE.format("default"))
    c = LexicalSimplificationPipeline(userId=userId, language=language)
    if not resources:
        try:
            resources = RESOURCES[language]
        except KeyError:
            print("Couldn't find resources for language {}".format(language))

    # Generator
    g = LexiGenerator(synonyms_files=resources["synonyms"],
                      embedding_files=resources["embeddings"])
    c.setGenerator(g)

    c.setCwi(LexiCWI("default", scorer=scorer))

    # Ranker
    c.setRanker(LexiRanker("default", scorer=scorer))
    c.cwi.scorer = scorer

    return c


c = fresh_train()

c.ranker.save("default")
c.cwi.save("default")
