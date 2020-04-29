from lexi.core.endpoints import process_html_lexical


def map_text_to_html_offsets(html_src):
    """
    Maps text offsets to HTML offsets, e.g. in HTML source `<p>One moring, when
    <a href="index.html">Georg Samsa</a> woke</p>`, text offset 0 (before 'One')
    is mapped to HTML offset 3 (after `<p>`).
    :param html_src: The HTML source in question
    :return: a dictinary mapping all text offsets to their corresponding HTML
    offset
    """
    mapping = {}
    text_idx = 0
    inside_tag = False
    for i, c in enumerate(html_src):
        if c == "<":
            inside_tag = True
        elif c == ">":
            inside_tag = False
        elif not inside_tag:
            mapping[text_idx] = i
            text_idx += 1
    return mapping


def process_html(pipeline, html_src, startOffset, endOffset, cwi, ranker,
                 mode="lexical", requestId=0, min_similarity=0.7,
                 blacklist=None):
    """
    :param pipeline:
    :param html_src: The HTML source in question
    :param ranker: CWI module to use with this classifier
    :param ranker: Ranker to use with this classifier
    :param mode: simplification mode (whether to perform lexical simplification,
     sentence simplification, ...). Only "lexical" accepted for now.
    :param requestId: Request identifier to disambiguate core simplification
    targets across multiple calls to this method
    :param min_similarity: minimum similarity for replacements, if applicable
    :param blacklist: list of words not to be simplified
    :return: processed text
    """
    simplifications = {}
    html_out = ""
    if mode == "lexical":
        _output, _simplifications = process_html_lexical(
            pipeline, html_src, startOffset, endOffset, requestId=requestId,
            cwi=cwi,
            ranker=ranker,
            min_similarity=min_similarity,
            blacklist=blacklist)
    else:
        # _output, _simplifications = process_html_structured(
        #     classifier, html_src, ranker, 0)
        raise NotImplementedError("Only 'lexical' simplification mode "
                                  "implemented so far. You specified {}.".
                                  format(mode))
    html_out += _output
    simplifications.update(_simplifications)
    return html_out, simplifications
