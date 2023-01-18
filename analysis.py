"""Implements a class and functions to simplify
drawing of graphs analysing token hits"""
import json
import itertools

import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from user_agents import parse

class TokenToGraph:
    """Represents a single token, which usually corresponds to a csv
    file. Contains the token hits, as well as meta information
    that AnalysisGraph uses. A TokenToGraph is passed to 
    AnalysisGraph which illustrates it.
    """

    def __init__(self, title, list_of_all_tokenhits):
        self.title = title
        self.tokenhits = list_of_all_tokenhits



class AnalysisGraph:
    """ Represents a graph that should be drawn. First
    define the graph via initialization, then call the draw() method with
    a list of tokenhits.
    The extraction_algorithm is a lambda function that returns whatever it is
    we want to group our hits by for graphing/analysis.
    For graphs that show something over time pass in over_time=True,
    this will automatically change graphing types and and show tokenhits
    relative to each other
    sort_function is usually the same as extraction_algorithm, but since
    internally we use a unix uniq-style function this needs to create an order
    that is equivalent (or at least compatible) with the extraction_algorithm)"""

    def __init__(self):
        # TODO accept multiple graphs, as list
        # TODO update function doc
        self.graph_names = []
        self.extraction_algorithms = []
        self.over_times = []

        self.data_source_list = []
        self.sort_functions = []


    def add_graph_definition(self, graph_name, extraction_algorithm, over_time=False, sort_function=None):
        self.graph_names.append(graph_name)
        self.extraction_algorithms.append(extraction_algorithm)
        self.over_times.append(over_time)

        if sort_function is None:
            sort_function = extraction_algorithm

        self.sort_functions.append(sort_function)

    def set_data_sources(self, list_of_TokenToGraphs):
        self.data_source_list = (list_of_TokenToGraphs)



    def draw(self):
        """Draws this AnalysisGraph and pops up the finished graph. Expects
        a list of TokenToGraphs, which contain TokenHits as defined in main.py"""
        # TODO DOCS
        fig= plt.figure()
        sns.set_theme()
        legend_names = []
        list_of_TokenToGraphs = self.data_source_list
        for token_to_graph in list_of_TokenToGraphs:
            legend_names.append(token_to_graph.title)


        for graph_definition_index in range(len(self.graph_names)):
            ax = fig.add_subplot(2,3, graph_definition_index+1)
            plt.title(self.graph_names[graph_definition_index])
            plt.xticks(rotation=45)

            if self.over_times[graph_definition_index]:
                plot = self._draw_continuous_plot(list_of_TokenToGraphs, graph_definition_index, ax)
            else:
                plot = self._draw_category_plot(list_of_TokenToGraphs, graph_definition_index, ax)
            ax.get_legend().remove()


        # legend is implicit and discouraged, but it's fine
        plt.figlegend(legend_names, loc='lower right',bbox_to_anchor=(0.85,0.25))
        plt.show()

    def _draw_continuous_plot(self, list_of_all_tokens, graph_definition_index,ax):
        # TODO doc
        token_dataframe = self._construct_dataframe_for_seaborn(list_of_all_tokens, graph_definition_index)
        return sns.scatterplot(x='Category', y='Value', hue='Token name', data=token_dataframe, ax=ax)

    def _draw_category_plot(self, list_of_all_tokens, graph_definition_index, ax):
        # TODO doc
        # Apply the extraction function to the list of all tokens
        token_dataframe = self._construct_dataframe_for_seaborn(list_of_all_tokens, graph_definition_index)
        return sns.barplot(x='Category', y='Value', hue='Token name', data=token_dataframe, ax=ax)


    def _construct_dataframe_for_seaborn(self, tokens_list, graph_definition_index):
        # TODO
        """ [category, token name, value],
        [category, token name, value]"""
        category_list = []
        token_name_list = []
        value_list = []

        for token in tokens_list:
            datapoints_of_token = self._get_datapoint_tuples_from_TokenToGraph(token, graph_definition_index)

            for datapoint in datapoints_of_token:
                category_list.append(datapoint[0])
                token_name_list.append(token.title)
                value_list.append(datapoint[1])

        token_dataframe = pd.DataFrame({'Category': category_list,
                'Token name': token_name_list,
                'Value': value_list})
        return token_dataframe


    def _get_datapoint_tuples_from_TokenToGraph(self, token_to_graph, graph_definition_index):
        # TODO 
        datapoint_tuples = []
        list_of_all_tokenhits = token_to_graph.tokenhits
        list_of_all_tokenhits.sort(key=self.sort_functions[graph_definition_index])
        if self.over_times[graph_definition_index]:
            # "buckets" for this are "this is the nth request",
            # so all buckets have size 1. This information is not contained
            # within a hit, it is relative,
            # so we run all our map functions over the hits (sorted
            # by our extraction algorithm) enriched with what their position
            datapoint_tuples = list(map(
                self.extraction_algorithms[graph_definition_index],
                list_of_all_tokenhits, range(len(list_of_all_tokenhits))))
        else:
            # Sort all hits into buckets
            for key, group in itertools.groupby(list_of_all_tokenhits, self.extraction_algorithms[graph_definition_index]):
                group_size = sum(1 for _ in group)
                datapoint_tuples.append((key,group_size))

        return datapoint_tuples



def build_graphs_over_time(graph):
    """Returns a list of all time-relative graphs
    we want to draw.
    """
    graph.add_graph_definition("Requests over time",
                lambda hit, position : (hit.timestamp, position),
                over_time=True,
                sort_function=lambda hit:hit.timestamp)
    return graph


def build_graphs_over_all(graph):
    """Returns a list of all graphs
    we want to draw that analyse all hits by some metric
    """
    graph.add_graph_definition("Requests by country",
        lambda hit: json.loads(hit.geo_info)["country"])

    graph.add_graph_definition("Requests by Region",
        lambda hit: json.loads(hit.geo_info)["region"])

    graph.add_graph_definition("Requests by browser family",
        lambda hit: parse(hit.useragent).browser.family)

    graph.add_graph_definition("Requests by os",
        lambda hit: parse(hit.useragent).os.family)

    graph.add_graph_definition("Requests by mobile devices",
        lambda hit: "Mobile" if parse(hit.useragent).is_mobile else "PC")
    return graph


def run_analyses(list_of_all_tokensToGraph):
    """Draws all graphs defined in build_graphs_over_time
    and build_graphs_over_all"""
    # TODO Docs
    graph = AnalysisGraph()
    build_graphs_over_time(graph)
    build_graphs_over_all(graph)

    
    graph.set_data_sources(list_of_all_tokensToGraph)
    graph.draw()
